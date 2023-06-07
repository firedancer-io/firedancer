#include "../fd_tests.h"
int test_425(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 29;
  test.test_number = 425;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_425_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_425_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_425_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_425_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_425_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_425_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_425_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_425_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_425_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_425_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_425_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_425_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_425_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_425_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_425_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_425_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_425_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_425_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_425_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_425_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_425_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_425_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_426(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 357;
  test.test_number = 426;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_426_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_426_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_426_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_426_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_426_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_426_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_426_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_426_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_426_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_426_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_426_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_426_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_426_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_426_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_426_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_426_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_426_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_426_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_426_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_426_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_426_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_426_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_427(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 405;
  test.test_number = 427;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_427_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_427_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_427_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_427_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_427_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_427_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_427_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_427_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_427_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_427_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_427_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_427_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_427_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_427_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_427_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_427_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_427_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_427_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_427_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_427_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_427_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_427_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_428(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 435;
  test.test_number = 428;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_428_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_428_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_428_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_428_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_428_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_428_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_428_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_428_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_428_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_428_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_428_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_428_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_428_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_428_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_428_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_428_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_428_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_428_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_428_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_428_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_428_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_428_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_429(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 467;
  test.test_number = 429;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_429_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_429_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_429_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_429_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_429_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_429_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_429_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_429_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_429_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_429_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_429_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_429_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_429_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_429_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_429_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_429_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_429_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_429_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_429_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_429_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_429_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_429_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_430(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 499;
  test.test_number = 430;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_430_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_430_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_430_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_430_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_430_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_430_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_430_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_430_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_430_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_430_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_430_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_430_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_430_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_430_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_430_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_430_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_430_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_430_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_430_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_430_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_430_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_430_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_431(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 525;
  test.test_number = 431;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9DwLyQKMvw3pgnfyoUHJtiVYgduTkLRosAHsW4Uj4XCh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_431_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_431_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_431_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_431_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CNbZgQiy1vG1fgxCzHDyhV9mwjZyxayRWqDfgywDSuxV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_431_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_431_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_431_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_431_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FuxXmjYxaAXUW4Y4QbNDjbzQqDdgHVq36s6c6B5xqAd2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_431_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_431_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_431_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_431_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_431_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_431_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_431_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_431_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_431_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_431_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_431_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_431_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_431_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_431_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_432(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 202;
  test.test_number = 432;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_432_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_432_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_432_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_432_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_432_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_432_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_432_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_432_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_432_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_432_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_432_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_432_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_432_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_432_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_432_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_432_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_432_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_432_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_432_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_432_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_432_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_432_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_433(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 275;
  test.test_number = 433;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_433_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_433_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_433_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_433_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_433_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_433_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_433_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_433_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_433_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_433_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_433_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_433_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_433_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_433_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_433_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_433_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_433_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_433_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_433_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_433_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_433_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_433_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_434(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 31;
  test.test_number = 434;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_434_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_434_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_434_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_434_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_434_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_434_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_434_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_434_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_434_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_434_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_434_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_434_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_434_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_434_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_434_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_434_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_434_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_434_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_434_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_434_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_434_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_434_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_435(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 329;
  test.test_number = 435;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_435_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_435_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_435_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_435_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_435_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_435_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_435_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_435_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_435_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_435_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_435_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_435_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_435_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_435_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_435_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_435_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_435_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_435_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_435_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_435_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_435_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_435_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_436(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 389;
  test.test_number = 436;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_436_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_436_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_436_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_436_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_436_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_436_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_436_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_436_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_436_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_436_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_436_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_436_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_436_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_436_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_436_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_436_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_436_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_436_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_436_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_436_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_436_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_436_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_437(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 449;
  test.test_number = 437;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_437_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_437_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_437_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_437_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_437_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_437_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_437_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_437_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_437_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_437_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_437_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_437_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_437_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_437_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_437_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_437_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_437_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_437_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_437_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_437_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_437_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_437_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_438(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 499;
  test.test_number = 438;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_438_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_438_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_438_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_438_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_438_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_438_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_438_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_438_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_438_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_438_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_438_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_438_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_438_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_438_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_438_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_438_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_438_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_438_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_438_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_438_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_438_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_438_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_439(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,116,55,89,126,78,111,108,29,90,127,87,114,106,75,82,98,80,120,117,24,125,76,30,26,123,112,56,2,118,79,110,109,62,61,92,124,27,105,121,77,103,33,113,15,128,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_invalid_account_data::old_behavior";
  test.test_nonce  = 529;
  test.test_number = 439;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7JmkgH4TGk4Qwvu27SaXnKKBMLjkfm9BBQxzWrsSrmgL",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_439_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_439_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_439_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_439_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8sH2rvnWKB54JPyddP8u14h3qPXFnBYzURQ23NHDr57o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_439_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_439_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_439_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_439_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7hFT2MmRruzdhBbkVVqkSvttQYuVkMmFboZjtafq9d4j",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_439_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_439_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_439_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_439_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_439_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_439_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_439_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_439_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_439_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_439_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_439_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_439_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_439_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_439_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_440(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 169;
  test.test_number = 440;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_440_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_440_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_440_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_440_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_440_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_440_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_440_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_440_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_440_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_440_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_440_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_440_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_440_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_440_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_440_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_440_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_440_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_440_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_440_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_440_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_440_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_440_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_441(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 23;
  test.test_number = 441;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_441_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_441_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_441_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_441_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_441_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_441_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_441_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_441_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_441_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_441_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_441_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_441_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_441_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_441_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_441_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_441_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_441_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_441_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_441_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_441_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_441_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_441_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_442(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 344;
  test.test_number = 442;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_442_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_442_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_442_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_442_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_442_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_442_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_442_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_442_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_442_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_442_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_442_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_442_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_442_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_442_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_442_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_442_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_442_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_442_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_442_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_442_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_442_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_442_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_443(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 392;
  test.test_number = 443;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_443_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_443_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_443_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_443_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_443_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_443_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_443_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_443_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_443_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_443_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_443_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_443_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_443_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_443_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_443_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_443_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_443_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_443_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_443_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_443_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_443_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_443_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_444(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 453;
  test.test_number = 444;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_444_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_444_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_444_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_444_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_444_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_444_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_444_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_444_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_444_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_444_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_444_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_444_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_444_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_444_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_444_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_444_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_444_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_444_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_444_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_444_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_444_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_444_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_445(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 503;
  test.test_number = 445;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_445_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_445_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_445_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_445_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_445_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_445_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_445_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_445_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_445_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_445_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_445_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_445_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_445_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_445_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_445_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_445_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_445_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_445_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_445_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_445_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_445_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_445_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_446(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 534;
  test.test_number = 446;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_446_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_446_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_446_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_446_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_446_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_446_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_446_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_446_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_446_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_446_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_446_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_446_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_446_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_446_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_446_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_446_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_446_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_446_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_446_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_446_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_446_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_446_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_447(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 567;
  test.test_number = 447;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "93hptfC9UWn3mvN4rEx6sAWbok3s91wQ1PVXqShEKWte",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_447_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_447_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_447_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_447_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9u9DoyGWh8bXJiefBqSjrxyhMwtgARKhCJsyZu5n2Wjn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_447_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_447_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_447_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_447_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "42W4AwN1fmapAR8mNti3NTr8dfMhMHb2ekub5ALN1GTb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_447_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_447_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_447_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_447_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_447_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_447_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_447_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_447_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_447_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_447_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_447_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_447_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_447_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_447_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_448(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 14;
  test.test_number = 448;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_448_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_448_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_448_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_448_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_448_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_448_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_448_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_448_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_448_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_448_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_448_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_448_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_448_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_448_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_448_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_448_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_448_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_448_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_448_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_448_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_448_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_448_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_449(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 238;
  test.test_number = 449;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_449_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_449_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_449_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_449_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_449_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_449_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_449_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_449_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_449_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_449_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_449_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_449_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_449_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_449_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_449_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_449_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_449_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_449_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_449_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_449_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_449_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_449_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
