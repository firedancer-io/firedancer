#include "../fd_tests.h"
int test_1250(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 474;
  test.test_number = 1250;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111121kM4krX4fLevQHMeaFdXoJjrtecioCAdBM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1250_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1250_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1250_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1250_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111229gfjxpMNX7oDiVjbfxrHS1eX9sfWRkTVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1250_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1250_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1250_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1250_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1250_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1250_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1250_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1250_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1250_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1250_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1251(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 545;
  test.test_number = 1251;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111127P5WYNh6bs9BrMJrv8Hzb4YshiDvkULHcB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1251_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1251_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1251_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1251_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111127nR7XUzPK3c4fnSwwYdK5BpfLDUsThv7vX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1251_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1251_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1251_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1251_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1251_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1251_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1251_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1251_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1251_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1251_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1252(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 293;
  test.test_number = 1252;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1252_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1252_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1252_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1252_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111fdSuXRcfAKV7WcPKMGybZ38XRRjZFUzyN7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1252_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1252_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1252_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1252_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1252_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1252_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1252_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1252_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111fE7JYKKNT92EhBFEKreH4urjnvUcYFR93m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1252_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1252_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1252_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1252_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1252_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1252_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1252_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1252_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1252_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1252_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1253(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 368;
  test.test_number = 1253;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ir9jQHzxqmC845W1Yde9S3JpTTo6wMfdts",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1253_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1253_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1253_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1253_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1253_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1253_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1253_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1253_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1253_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1253_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1253_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1253_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111iSp8RBhg8ajFEeMvXDJpwv32pxYAE85oaX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1253_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1253_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1253_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1253_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1253_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1253_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1253_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1253_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1253_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1253_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1254(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 480;
  test.test_number = 1254;
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
  test_acc->data            = fd_flamenco_native_prog_test_1254_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1254_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1254_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1254_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111122Z2Gj57e5hag39dpd6JAmZHS9f8cDfLHp3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1254_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1254_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1254_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1254_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111122xMsiBQvnt3YramueWdVFgZDnAPYvtv88P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1254_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1254_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1254_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1254_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1254_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1254_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1254_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1254_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1254_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1254_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1255(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 485;
  test.test_number = 1255;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1255_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1255_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1255_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1255_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111124ANgfWJnvRSBJtCAimdSi4NafgAP4bfd5R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1255_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1255_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1255_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1255_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111123m35gQ1WDEyJVT45hMJ8Dw6o3AuSMN5nm5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1255_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1255_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1255_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1255_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1255_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1255_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1255_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1255_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1255_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1255_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1256(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 489;
  test.test_number = 1256;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111124y3tdiuNLnMvwkULmcJ5gJv9vggGV4qHi7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1256_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1256_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1256_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1256_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1256_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1256_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1256_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1256_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1256_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1256_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1256_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1256_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1256_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1256_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1257(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 554;
  test.test_number = 1257;
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
  test_acc->data            = fd_flamenco_native_prog_test_1257_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1257_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1257_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1257_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1257_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1257_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1257_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1257_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112ACSjS8n7a8PKaPHU64dDywTP7F2Xj7R7pb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1257_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1257_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1257_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1257_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111129o78T2UprwvSkx9P4eHuVpBbUjmb1sqHWF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1257_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1257_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1257_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1257_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1257_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1257_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1258(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 566;
  test.test_number = 1258;
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
  test_acc->data            = fd_flamenco_native_prog_test_1258_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1258_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1258_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1258_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1258_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1258_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1258_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1258_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112BQTYPTfyhfmx2ghjAKdBSKGjzkoMrpAcmd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1258_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1258_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1258_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1258_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112CD8kMgGZ82hhfYyuDAHpQZpKFmKFHHLHQK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1258_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1258_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1258_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1258_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1258_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1258_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1259(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 575;
  test.test_number = 1259;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112DpVAJ7ThxkZCwHYFJqd6M4uTmnM28Dfcfh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1259_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1259_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1259_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1259_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1259_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1259_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1259_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1259_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1259_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1259_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1259_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1259_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1259_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1259_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1260(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 302;
  test.test_number = 1260;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "79oBSbxvAux5paSKrucgqEU4JdApKLF2oFCCRCLzG8RB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1260_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1260_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1260_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1260_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cCotRfd8NS2czc61ee5JJzwoBcpvq9djGmnC1p5NTNt",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1260_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1260_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1260_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1260_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oUK6p6mFrroaSDpAANYnFN8HHcRkXDpQEb5DJPRG1g5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1260_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1260_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1260_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1260_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1260_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1260_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1260_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1260_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1260_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1260_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1260_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1260_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1260_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1260_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1261(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 410;
  test.test_number = 1261;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "79oBSbxvAux5paSKrucgqEU4JdApKLF2oFCCRCLzG8RB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1261_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1261_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1261_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1261_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cCotRfd8NS2czc61ee5JJzwoBcpvq9djGmnC1p5NTNt",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1261_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1261_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1261_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1261_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oUK6p6mFrroaSDpAANYnFN8HHcRkXDpQEb5DJPRG1g5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1261_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1261_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1261_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1261_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1261_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1261_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1261_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1261_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1261_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1261_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1261_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1261_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1261_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1261_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1262(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 473;
  test.test_number = 1262;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "79oBSbxvAux5paSKrucgqEU4JdApKLF2oFCCRCLzG8RB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1262_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1262_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1262_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1262_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cCotRfd8NS2czc61ee5JJzwoBcpvq9djGmnC1p5NTNt",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1262_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1262_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1262_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1262_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oUK6p6mFrroaSDpAANYnFN8HHcRkXDpQEb5DJPRG1g5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1262_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1262_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1262_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1262_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1262_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1262_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1262_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1262_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1262_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1262_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1262_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1262_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1262_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1262_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1263(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 511;
  test.test_number = 1263;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "79oBSbxvAux5paSKrucgqEU4JdApKLF2oFCCRCLzG8RB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1263_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1263_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1263_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1263_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "cCotRfd8NS2czc61ee5JJzwoBcpvq9djGmnC1p5NTNt",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1263_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1263_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1263_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1263_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oUK6p6mFrroaSDpAANYnFN8HHcRkXDpQEb5DJPRG1g5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1263_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1263_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1263_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1263_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1263_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1263_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1263_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1263_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1263_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1263_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1263_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1263_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1263_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1263_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1264(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 248;
  test.test_number = 1264;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6RiUZWAmNgU9hXhCCXMJ95JdQwgiv7N8g8iLQT1SRVkL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1264_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1264_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1264_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1264_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FW5TwWggK7xYZC9D5dWP47v32TQ9DY1sa9SmGUCo7QPu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1264_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1264_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1264_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1264_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3ryt441LPr66WL4HkvE2TCabAzNn6iykNtew3zzkVa5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1264_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1264_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1264_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1264_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1264_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1264_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1264_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1264_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1264_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1264_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1264_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1264_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1264_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1264_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1265(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 391;
  test.test_number = 1265;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6RiUZWAmNgU9hXhCCXMJ95JdQwgiv7N8g8iLQT1SRVkL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1265_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1265_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1265_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1265_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FW5TwWggK7xYZC9D5dWP47v32TQ9DY1sa9SmGUCo7QPu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1265_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1265_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1265_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1265_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3ryt441LPr66WL4HkvE2TCabAzNn6iykNtew3zzkVa5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1265_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1265_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1265_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1265_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1265_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1265_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1265_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1265_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1265_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1265_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1265_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1265_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1265_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1265_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1266(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 448;
  test.test_number = 1266;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6RiUZWAmNgU9hXhCCXMJ95JdQwgiv7N8g8iLQT1SRVkL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1266_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1266_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1266_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1266_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FW5TwWggK7xYZC9D5dWP47v32TQ9DY1sa9SmGUCo7QPu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1266_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1266_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1266_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1266_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3ryt441LPr66WL4HkvE2TCabAzNn6iykNtew3zzkVa5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1266_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1266_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1266_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1266_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1266_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1266_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1266_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1266_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1266_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1266_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1266_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1266_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1266_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1266_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1267(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,27,103,33,87,126,79,105,110,62,56,106,24,82,78,29,112,128,77,30,80,118,108,113,117,83,89,76,2,114,116,127,26,98,61,125,120,111,121,55,75,122,90,109,15,124,123 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::new_behavior";
  test.test_nonce  = 505;
  test.test_number = 1267;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6RiUZWAmNgU9hXhCCXMJ95JdQwgiv7N8g8iLQT1SRVkL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1267_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1267_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1267_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1267_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FW5TwWggK7xYZC9D5dWP47v32TQ9DY1sa9SmGUCo7QPu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1267_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1267_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1267_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1267_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3ryt441LPr66WL4HkvE2TCabAzNn6iykNtew3zzkVa5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1267_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1267_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1267_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1267_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1267_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1267_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1267_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1267_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1267_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1267_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1267_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1267_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1267_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1267_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1268(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 112,117,62,108,106,78,114,109,15,80,79,33,89,128,118,2,76,126,90,82,75,26,98,111,77,110,27,122,116,120,123,29,24,87,125,61,83,55,30,124,113,92,56,103,105,127,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 304;
  test.test_number = 1268;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DtFQo7XFZaTX5BXF4Cb1RtXu9fNhCcZSg9zuE3zcyUiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1268_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1268_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1268_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1268_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DJWq62exscEce1ynEAo19aqoTZ9dSzMPNe6t9DCLSMug",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1268_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1268_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1268_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1268_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DLnWEPe273pG1H2SWBRRKEJBB3yjiEvBaZuqChdzCq33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1268_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1268_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1268_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1268_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1268_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1268_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1268_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1268_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1268_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1268_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1268_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1268_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1268_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1268_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1269(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 112,117,62,108,106,78,114,109,15,80,79,33,89,128,118,2,76,126,90,82,75,26,98,111,77,110,27,122,116,120,123,29,24,87,125,61,83,55,30,124,113,92,56,103,105,127,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 408;
  test.test_number = 1269;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DtFQo7XFZaTX5BXF4Cb1RtXu9fNhCcZSg9zuE3zcyUiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1269_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1269_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1269_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1269_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DJWq62exscEce1ynEAo19aqoTZ9dSzMPNe6t9DCLSMug",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1269_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1269_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1269_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1269_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DLnWEPe273pG1H2SWBRRKEJBB3yjiEvBaZuqChdzCq33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1269_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1269_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1269_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1269_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1269_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1269_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1269_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1269_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1269_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1269_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1269_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1269_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1269_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1269_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1270(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 112,117,62,108,106,78,114,109,15,80,79,33,89,128,118,2,76,126,90,82,75,26,98,111,77,110,27,122,116,120,123,29,24,87,125,61,83,55,30,124,113,92,56,103,105,127,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 466;
  test.test_number = 1270;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DtFQo7XFZaTX5BXF4Cb1RtXu9fNhCcZSg9zuE3zcyUiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1270_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1270_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1270_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1270_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DJWq62exscEce1ynEAo19aqoTZ9dSzMPNe6t9DCLSMug",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1270_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1270_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1270_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1270_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DLnWEPe273pG1H2SWBRRKEJBB3yjiEvBaZuqChdzCq33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1270_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1270_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1270_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1270_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1270_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1270_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1270_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1270_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1270_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1270_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1270_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1270_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1270_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1270_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1271(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 112,117,62,108,106,78,114,109,15,80,79,33,89,128,118,2,76,126,90,82,75,26,98,111,77,110,27,122,116,120,123,29,24,87,125,61,83,55,30,124,113,92,56,103,105,127,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 490;
  test.test_number = 1271;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DtFQo7XFZaTX5BXF4Cb1RtXu9fNhCcZSg9zuE3zcyUiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1271_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1271_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1271_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1271_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DJWq62exscEce1ynEAo19aqoTZ9dSzMPNe6t9DCLSMug",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1271_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1271_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1271_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1271_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DLnWEPe273pG1H2SWBRRKEJBB3yjiEvBaZuqChdzCq33",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1271_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1271_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1271_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1271_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1271_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1271_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1271_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1271_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1271_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1271_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1271_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1271_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1271_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1271_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1272(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 236;
  test.test_number = 1272;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FPGBVBEffFvScpBJ1Vucw9CfzSbFtiBDoDRYLZcnnje3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1272_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1272_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1272_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1272_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKvTbjA8MNrCmWSkLLkcNb5AUBxX5jNT4CZcky9qTgbM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1272_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1272_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1272_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1272_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EP5DLKmbWZ66PjyrrefCk9kKGefuFtfT5iksvCUpmuch",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1272_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1272_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1272_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1272_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1272_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1272_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1272_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1272_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1272_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1272_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1272_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1272_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1272_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1272_raw_sz;
  test.expected_result = -26;
  test.custom_err = 1;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1273(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 361;
  test.test_number = 1273;
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
  test_acc->data            = fd_flamenco_native_prog_test_1273_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1273_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1273_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1273_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKvTbjA8MNrCmWSkLLkcNb5AUBxX5jNT4CZcky9qTgbM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1273_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1273_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1273_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1273_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EP5DLKmbWZ66PjyrrefCk9kKGefuFtfT5iksvCUpmuch",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1273_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1273_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1273_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1273_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1273_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1273_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1273_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1273_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1273_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1273_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1273_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1273_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1273_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1273_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1274(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_lockup::old_behavior";
  test.test_nonce  = 401;
  test.test_number = 1274;
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
  test_acc->data            = fd_flamenco_native_prog_test_1274_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1274_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1274_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1274_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BKvTbjA8MNrCmWSkLLkcNb5AUBxX5jNT4CZcky9qTgbM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1274_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1274_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1274_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1274_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EP5DLKmbWZ66PjyrrefCk9kKGefuFtfT5iksvCUpmuch",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1274_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1274_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1274_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1274_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1274_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1274_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1274_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1274_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1274_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1274_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1274_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1274_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1274_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1274_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
