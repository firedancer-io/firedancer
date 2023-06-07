#include "../fd_tests.h"
int test_950(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 412;
  test.test_number = 950;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_950_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_950_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_950_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_950_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_950_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_950_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_950_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_950_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111sJFQ5aG1kYvXEBRq4Sdqcg2Lg4CusGv8Y7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_950_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_950_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_950_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_950_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111rtuo6Txj3NTeQkHk32JX8YkZ3YwyA3LJDm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_950_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_950_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_950_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_950_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_950_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_950_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_951(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 177;
  test.test_number = 951;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_951_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_951_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_951_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_951_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_951_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_951_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_951_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_951_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_951_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_951_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_951_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_951_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RYco4dBaK1GStSWHVbKSaebzPmiYNHapJ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_951_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_951_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_951_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_951_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_951_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_951_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_952(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 212;
  test.test_number = 952;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_952_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_952_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_952_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_952_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Xz2SpMxBftgTyNjftJeYLexaTqqdk2v9MZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_952_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_952_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_952_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_952_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_952_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_952_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_952_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_952_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_952_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_952_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_952_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_952_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_952_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_952_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_953(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 419;
  test.test_number = 953;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111qgtz994ruq51xSsUxmJZgAwCA3B92LaoGj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_953_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_953_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_953_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_953_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111qHZPA2maCec991jPwLyFC3fQXXvCK6zxxP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_953_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_953_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_953_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_953_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_953_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_953_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_953_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_953_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_953_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_953_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_953_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_953_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_953_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_953_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_954(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 447;
  test.test_number = 954;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_954_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_954_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_954_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_954_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111x8JdtsqUGiV33P6sMUdfSBHnE7JEQ5v8LF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_954_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_954_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_954_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_954_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_954_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_954_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_954_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_954_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_954_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_954_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_954_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_954_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111xXeEsz8kytwurpExNtxyvJZZrcZB7KVxeb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_954_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_954_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_954_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_954_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_954_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_954_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_955(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 475;
  test.test_number = 955;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_955_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_955_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_955_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_955_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_955_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_955_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_955_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_955_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111vvHpwYwc9B6Qb5gcHDdhyoURLbXQGPAdPD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_955_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_955_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_955_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_955_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_955_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_955_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_955_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_955_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111wKdRvfEtrMZHQWphJdy2TvkCy6nLyckThZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_955_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_955_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_955_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_955_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_955_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_955_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_956(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 483;
  test.test_number = 956;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_956_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_956_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_956_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_956_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111123MhUhHiDW4WRg1uzfvxojoq1QfeVe8VxSj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_956_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_956_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_956_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_956_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_956_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_956_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_956_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_956_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_956_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_956_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_957(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 492;
  test.test_number = 957;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111z8zepRKupcoR8YoJUaJFroeiNdawxFqHuy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_957_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_957_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_957_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_957_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_957_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_957_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_957_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_957_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_957_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_957_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_957_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_957_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_957_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_957_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_958(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 487;
  test.test_number = 958;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_958_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_958_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_958_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_958_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111124ZiHecc5dbu48KLFkBxmCBeNJBRKmqFTPm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_958_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_958_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_958_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_958_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_958_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_958_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_958_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_958_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_958_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_958_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_959(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 506;
  test.test_number = 959;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111zYLFoXdCXoGHwywPVzdaLvvW18qtfVR8EK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_959_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_959_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_959_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_959_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_959_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_959_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_959_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_959_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_959_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_959_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_959_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_959_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_959_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_959_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_960(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 279;
  test.test_number = 960;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111dcktbt8DcRAjRSgtEBK18QmbGuSqhK5onP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_960_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_960_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_960_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_960_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_960_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_960_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_960_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_960_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_960_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_960_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_960_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_960_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111e26VazRWKbdcEspyFbeKcY3NuQhnQYfe6j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_960_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_960_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_960_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_960_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_960_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_960_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_960_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_960_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_960_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_960_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_961(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 369;
  test.test_number = 961;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111mfWxJ45yp2SFn7UciZyNpvDKrzbhuzkU7H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_961_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_961_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_961_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_961_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_961_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_961_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_961_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_961_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111mGBMJwnh6qyNxgLXh9e4LnwYEVLmCmAdnw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_961_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_961_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_961_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_961_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_961_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_961_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_961_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_961_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_961_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_961_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_961_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_961_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_961_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_961_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_962(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 274;
  test.test_number = 962;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_962_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_962_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_962_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_962_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_962_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_962_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_962_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_962_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZziTjuSdDnzr4YS71QK8mHKWcN8MJCqJwH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_962_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_962_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_962_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_962_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_962_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_962_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_962_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_962_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_962_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_962_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_962_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_962_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_962_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_962_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_963(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 388;
  test.test_number = 963;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111nUCAGGgZEPN1QyknmQe1oAku817bLTv8jy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_963_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_963_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_963_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_963_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_963_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_963_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_963_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_963_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111n4rZHAPGXCu8bYchjzJhK3V7VVredELJRd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_963_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_963_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_963_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_963_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_963_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_963_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_963_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_963_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_963_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_963_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_963_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_963_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_963_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_963_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_964(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 492;
  test.test_number = 964;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111125mj6bwVwm9HgackWpSxieZTjBhC9uXzxLo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_964_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_964_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_964_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_964_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111125NPVcqCf3xpomBcRo2dQASBwZBwDCJR82T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_964_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_964_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_964_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_964_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_964_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_964_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_964_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_964_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_964_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_964_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_964_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_964_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_964_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_964_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_965(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 510;
  test.test_number = 965;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111121M1TmkDmxAC3arDZYqJDKBU5G9Mn5xans1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_965_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_965_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_965_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_965_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111121kM4krX4fLevQHMeaFdXoJjrtecioCAdBM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_965_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_965_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_965_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_965_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_965_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_965_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_965_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_965_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_965_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_965_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_965_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_965_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_965_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_965_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_966(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 496;
  test.test_number = 966;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111126B4hb3oEUKkZQ3tbqsJ38gjWpCT6cmanf9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_966_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_966_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_966_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_966_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111126yjuZGPotggK2vAmthxg6wH65Cxz3EkTHq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_966_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_966_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_966_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_966_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111126aQJaA6XBWDSDV2gsHdMcp1JShi3L1AcyV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_966_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_966_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_966_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_966_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_966_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_966_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_966_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_966_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_966_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_966_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_966_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_966_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_966_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_966_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_966_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_966_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_966_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_966_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_967(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 519;
  test.test_number = 967;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111122xMsiBQvnt3YramueWdVFgZDnAPYvtv88P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_967_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_967_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_967_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_967_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_967_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_967_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_967_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_967_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_967_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_967_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_967_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_967_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111123m35gQ1WDEyJVT45hMJ8Dw6o3AuSMN5nm5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_967_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_967_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_967_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_967_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111123MhUhHiDW4WRg1uzfvxojoq1QfeVe8VxSj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_967_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_967_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_967_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_967_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_967_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_967_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_967_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_967_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_967_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_967_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_968(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 149;
  test.test_number = 968;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_968_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_968_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_968_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_968_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_968_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_968_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_968_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_968_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_968_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_968_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_968_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_968_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_968_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_968_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_968_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_968_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_968_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_968_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_968_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_968_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_968_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_968_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_969(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 183;
  test.test_number = 969;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_969_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_969_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_969_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_969_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_969_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_969_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_969_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_969_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111F5q7ToS5rKDfdAt2rgf9yPXY2f21tCRA55",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_969_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_969_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_969_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_969_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_969_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_969_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_969_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_969_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_969_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_969_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_970(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 168;
  test.test_number = 970;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_970_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_970_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_970_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_970_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_970_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_970_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_970_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_970_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_970_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_970_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_970_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_970_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_970_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_970_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_970_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_970_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_970_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_970_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_970_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_970_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_970_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_970_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_971(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 192;
  test.test_number = 971;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_971_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_971_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_971_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_971_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_971_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_971_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_971_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_971_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111F5q7ToS5rKDfdAt2rgf9yPXY2f21tCRA55",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_971_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_971_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_971_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_971_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_971_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_971_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_971_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_971_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_971_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_971_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_972(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 221;
  test.test_number = 972;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_972_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_972_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_972_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_972_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_972_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_972_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_972_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_972_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_972_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_972_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_972_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_972_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_972_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_972_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_972_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_972_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_972_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_972_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_973(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 303;
  test.test_number = 973;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_973_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_973_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_973_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_973_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_973_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_973_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_973_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_973_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_973_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_973_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_973_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_973_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_973_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_973_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_973_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_973_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_973_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_973_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_974(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,126,124,26,56,62,121,109,80,112,125,105,30,128,33,2,116,90,127,113,79,82,114,111,77,87,123,61,122,55,103,106,110,15,29,108,118,83,78,117,120,75,98,89,24,27,76 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_checked_instructions::new_behavior";
  test.test_nonce  = 228;
  test.test_number = 974;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111EgVWUh8o98knojjwqGKqVGFkQ9m5AxqKkj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_974_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_974_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_974_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_974_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111EH9uVaqWRxHuzJbroqzX18yxmeW8TjFVSP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_974_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_974_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_974_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_974_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_974_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_974_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_974_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_974_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_974_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_974_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_974_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_974_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_974_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_974_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
