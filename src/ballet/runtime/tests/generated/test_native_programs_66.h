#include "../fd_tests.h"
int test_1650(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,29,110,117,121,26,76,80,27,106,128,15,56,126,120,82,112,122,111,125,87,78,75,127,124,62,2,109,118,113,83,89,116,105,108,77,30,61,98,92,79,123,33,90,24,114,103 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 88;
  test.test_number = 1650;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZziTjuSdDnzr4YS71QK8mHKWcN8MJCqJwH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111aQ44j1juvyTisyaC2peTFQbJEsPJ1SR9Fd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1650_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1650_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1650_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1650_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1650_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1650_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1651(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,29,110,117,121,26,76,80,27,106,128,15,56,126,120,82,112,122,111,125,87,78,75,127,124,62,2,109,118,113,83,89,116,105,108,77,30,61,98,92,79,123,33,90,24,114,103 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 89;
  test.test_number = 1651;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111aQ44j1juvyTisyaC2peTFQbJEsPJ1SR9Fd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZziTjuSdDnzr4YS71QK8mHKWcN8MJCqJwH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1651_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1651_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1651_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1651_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1651_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1651_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1652(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 33,89,62,90,108,87,112,127,103,78,80,105,27,111,61,126,106,118,117,121,123,114,77,26,29,75,24,116,92,83,56,98,124,125,113,110,79,76,82,55,30,122,120,2,15,109,128 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 90;
  test.test_number = 1652;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111aoPfi83Ce9vbhQiH4EymjXs5sNeEifzyZy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1652_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1652_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1652_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1652_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1652_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1652_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1652_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1652_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1652_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1652_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1652_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1652_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1652_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1652_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1652_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1652_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1652_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1652_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1652_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1652_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111bCjGhELVMLPUWqrN5fK6Df8sVsuBRuaotK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1652_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1652_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1652_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1652_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1652_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1652_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1653(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 33,89,62,90,108,87,112,127,103,78,80,105,27,111,61,126,106,118,117,121,123,114,77,26,29,75,24,116,92,83,56,98,124,125,113,110,79,76,82,55,30,122,120,2,15,109,128 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 90;
  test.test_number = 1653;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111aoPfi83Ce9vbhQiH4EymjXs5sNeEifzyZy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1653_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1653_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1653_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1653_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1653_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1653_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1653_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1653_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1653_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1653_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1653_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1653_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111bCjGhELVMLPUWqrN5fK6Df8sVsuBRuaotK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1653_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1653_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1653_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1653_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1653_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1653_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1653_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1653_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1653_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1653_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1653_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1653_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1653_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1653_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1654(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 87,80,56,116,114,105,27,118,78,126,98,62,2,82,109,15,83,77,122,79,128,33,106,121,125,30,90,61,117,108,76,124,123,24,26,113,29,110,103,112,92,89,55,111,120,127,75 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 75;
  test.test_number = 1654;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1654_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1654_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1654_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1654_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1654_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1654_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1654_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1654_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1654_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1654_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1654_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1654_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1654_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1654_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1654_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1654_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1654_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1654_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1654_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1654_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1654_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1654_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1654_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1654_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1654_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1654_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1655(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 87,80,56,116,114,105,27,118,78,126,98,62,2,82,109,15,83,77,122,79,128,33,106,121,125,30,90,61,117,108,76,124,123,24,26,113,29,110,103,112,92,89,55,111,120,127,75 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 72;
  test.test_number = 1655;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1655_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1655_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1655_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1655_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1655_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1655_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1655_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1655_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1655_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1655_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1655_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1655_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1655_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1655_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1655_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1655_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1655_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1655_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1655_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1655_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1655_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1655_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1655_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1655_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1655_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1655_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1656(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,29,79,125,61,76,108,110,89,78,30,83,98,75,15,92,118,90,2,121,33,77,113,114,122,55,56,116,120,106,126,112,103,26,123,27,62,80,124,117,109,127,111,87,82,105,24 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 84;
  test.test_number = 1656;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1656_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1656_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1656_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1656_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1656_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1656_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1656_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1656_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1656_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1656_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1656_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1656_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1656_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1656_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1656_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1656_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1656_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1656_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1656_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1656_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1656_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1656_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1657(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 128,29,79,125,61,76,108,110,89,78,30,83,98,75,15,92,118,90,2,121,33,77,113,114,122,55,56,116,120,106,126,112,103,26,123,27,62,80,124,117,109,127,111,87,82,105,24 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 84;
  test.test_number = 1657;
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
  test_acc->data            = fd_flamenco_native_prog_test_1657_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1657_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1657_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1657_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1657_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1657_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1657_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1657_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1657_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1657_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1657_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1657_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1657_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1657_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1657_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1657_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1657_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1657_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1657_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1657_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1657_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1657_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1658(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 76,82,126,92,27,125,105,116,83,113,30,33,117,109,75,121,123,98,79,127,24,56,120,103,87,106,128,118,110,2,62,108,124,114,29,112,61,122,15,111,78,26,80,89,90,55,77 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 86;
  test.test_number = 1658;
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
  test_acc->data            = fd_flamenco_native_prog_test_1658_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1658_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1658_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1658_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1658_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1658_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1658_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1658_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1658_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1658_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1658_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1658_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1658_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1658_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1658_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1658_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1658_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1658_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1658_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1658_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1658_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1658_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1659(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 76,82,126,92,27,125,105,116,83,113,30,33,117,109,75,121,123,98,79,127,24,56,120,103,87,106,128,118,110,2,62,108,124,114,29,112,61,122,15,111,78,26,80,89,90,55,77 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 87;
  test.test_number = 1659;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1659_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1659_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1659_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1659_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1659_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1659_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1659_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1659_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1659_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1659_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1659_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1659_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1659_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1659_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1659_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1659_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1659_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1659_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1659_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1659_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1659_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1659_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1660(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,33,110,121,120,61,114,128,2,125,26,90,109,82,108,77,103,126,76,98,55,75,56,62,29,112,92,27,106,122,78,116,30,87,127,80,83,113,89,111,118,79,117,15,124,24,105 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 21;
  test.test_number = 1660;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1660_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1660_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1660_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1660_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1660_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1660_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1660_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1660_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1660_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1660_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1660_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1660_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1660_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1660_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1660_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1660_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1660_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1660_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1661(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,62,92,87,75,76,113,122,110,120,56,83,15,118,108,90,26,114,111,128,116,103,80,24,30,106,123,127,29,33,121,124,82,27,117,98,79,77,125,78,61,112,109,105,2,55,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 60;
  test.test_number = 1661;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1661_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1661_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1661_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1661_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1661_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1661_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1661_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1661_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1661_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1661_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1661_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1661_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1661_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1661_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1661_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1661_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1661_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1661_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1662(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 33,69,80,75,88,74,42,52,123,16,83,67,98,103,73,48,79,5,63,10,93,13,107,105,125,43,22,89,68,20,124,35,55,117,38,121,21,94,92,112,72,51,126,101,9,61,41,71,27,47,82,97,58,109,85,11,104,6,90,113,102,14,2,65,53,122,12,118,106,24,57,39,120,7,45,110,3,87,15,19,128,23,34,95,28,60,59,1,26,8,115,32,56,84,18,46,4,64,70,66,108,40,96,119,54,36,91,111,99,100,31,86,127,81,50,62,44,0,76,114,29,77,30,116,17,49,25,37,78 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 69;
  test.test_number = 1662;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1662_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1662_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1662_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1662_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1662_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1662_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1662_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1662_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1662_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1662_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1662_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1662_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1662_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1662_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1662_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1662_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1662_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1662_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1663(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,90,55,26,33,108,122,124,92,106,110,123,112,128,127,98,114,82,118,87,121,15,105,116,56,24,120,83,27,2,61,113,111,77,103,29,30,79,78,75,125,80,117,62,126,89,76 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 9;
  test.test_number = 1663;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1663_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1663_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1663_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1663_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1663_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1663_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1663_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1663_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1663_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1663_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1663_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1663_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1663_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1663_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1663_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1663_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1663_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1663_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1664(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 104,70,12,62,93,91,117,69,73,77,59,37,72,88,122,109,1,50,63,106,21,123,116,71,44,5,57,7,110,10,51,115,6,26,41,2,90,22,76,18,65,80,119,29,108,28,36,75,68,24,105,52,43,47,0,97,34,96,103,107,40,32,101,39,78,48,23,118,95,8,120,102,31,98,49,79,128,3,124,74,11,33,125,25,16,54,94,35,58,86,15,64,66,53,81,127,87,85,27,121,99,19,83,113,55,112,60,61,100,14,126,38,84,30,111,17,67,13,42,9,92,4,20,82,45,89,56,114,46 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 72;
  test.test_number = 1664;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1664_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1664_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1664_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1664_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1664_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1664_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1664_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1664_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1664_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1664_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1664_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1664_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1664_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1664_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1664_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1664_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1664_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1664_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1665(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 104,70,12,62,93,91,117,69,73,77,59,37,72,88,122,109,1,50,63,106,21,123,116,71,44,5,57,7,110,10,51,115,6,26,41,2,90,22,76,18,65,80,119,29,108,28,36,75,68,24,105,52,43,47,0,97,34,96,103,107,40,32,101,39,78,48,23,118,95,8,120,102,31,98,49,79,128,3,124,74,11,33,125,25,16,54,94,35,58,86,15,64,66,53,81,127,87,85,27,121,99,19,83,113,55,112,60,61,100,14,126,38,84,30,111,17,67,13,42,9,92,4,20,82,45,89,56,114,46 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 12;
  test.test_number = 1665;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1665_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1665_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1665_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1665_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1665_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1665_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1665_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1665_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1665_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1665_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1665_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1665_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1665_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1665_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1665_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1665_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1665_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1665_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1666(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 104,70,12,62,93,91,117,69,73,77,59,37,72,88,122,109,1,50,63,106,21,123,116,71,44,5,57,7,110,10,51,115,6,26,41,2,90,22,76,18,65,80,119,29,108,28,36,75,68,24,105,52,43,47,0,97,34,96,103,107,40,32,101,39,78,48,23,118,95,8,120,102,31,98,49,79,128,3,124,74,11,33,125,25,16,54,94,35,58,86,15,64,66,53,81,127,87,85,27,121,99,19,83,113,55,112,60,61,100,14,126,38,84,30,111,17,67,13,42,9,92,4,20,82,45,89,56,114,46 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 23;
  test.test_number = 1666;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1666_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1666_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1666_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1666_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1666_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1666_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1666_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1666_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1666_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1666_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1666_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1666_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1666_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1666_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1666_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1666_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1666_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1666_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1667(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 104,70,12,62,93,91,117,69,73,77,59,37,72,88,122,109,1,50,63,106,21,123,116,71,44,5,57,7,110,10,51,115,6,26,41,2,90,22,76,18,65,80,119,29,108,28,36,75,68,24,105,52,43,47,0,97,34,96,103,107,40,32,101,39,78,48,23,118,95,8,120,102,31,98,49,79,128,3,124,74,11,33,125,25,16,54,94,35,58,86,15,64,66,53,81,127,87,85,27,121,99,19,83,113,55,112,60,61,100,14,126,38,84,30,111,17,67,13,42,9,92,4,20,82,45,89,56,114,46 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 59;
  test.test_number = 1667;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1667_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1667_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1667_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1667_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1667_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1667_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1667_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1667_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1667_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1667_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1667_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1667_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1667_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1667_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1667_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1667_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1667_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1667_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1668(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,29,75,30,121,124,110,122,108,105,98,61,62,55,83,82,79,27,125,117,116,15,127,106,90,77,56,87,26,33,123,92,2,118,128,114,103,126,120,76,109,24,89,111,80,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 34;
  test.test_number = 1668;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1668_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1668_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1668_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1668_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1668_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1668_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1668_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1668_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1668_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1668_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1668_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1668_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1668_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1668_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1668_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1668_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1668_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1668_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1669(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,29,75,30,121,124,110,122,108,105,98,61,62,55,83,82,79,27,125,117,116,15,127,106,90,77,56,87,26,33,123,92,2,118,128,114,103,126,120,76,109,24,89,111,80,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 36;
  test.test_number = 1669;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1669_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1669_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1669_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1669_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1669_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1669_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1669_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1669_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1669_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1669_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1669_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1669_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1669_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1669_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1669_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1669_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1669_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1669_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1670(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,29,75,30,121,124,110,122,108,105,98,61,62,55,83,82,79,27,125,117,116,15,127,106,90,77,56,87,26,33,123,92,2,118,128,114,103,126,120,76,109,24,89,111,80,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 47;
  test.test_number = 1670;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1670_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1670_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1670_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1670_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1670_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1670_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1670_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1670_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1670_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1670_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1670_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1670_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1670_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1670_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1670_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1670_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1670_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1670_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1671(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,87,78,2,24,29,98,127,80,33,105,124,79,125,92,112,55,113,61,126,75,82,15,118,77,121,83,116,90,106,30,122,120,103,111,110,89,114,27,56,128,109,108,26,117,76,62 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter_checked";
  test.test_nonce  = 49;
  test.test_number = 1671;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1671_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1671_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1671_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1671_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1671_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1671_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1671_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1671_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1671_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1671_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1671_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1671_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1671_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1671_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1671_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1671_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1671_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1671_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1672(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,105,27,2,116,114,109,15,111,127,56,87,24,30,29,33,117,55,78,122,124,98,82,77,123,26,128,118,121,75,120,62,113,126,125,110,103,108,80,83,92,106,90,76,112,79,61 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 50;
  test.test_number = 1672;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1672_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1672_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1672_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1672_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1672_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1672_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1672_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1672_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1672_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1672_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1672_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1672_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1672_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1672_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1673(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,89,56,30,118,92,62,27,123,113,106,55,114,109,61,128,26,2,79,76,82,125,78,120,117,103,33,29,121,112,90,110,108,124,15,75,122,83,77,87,126,80,111,116,127,105,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 8;
  test.test_number = 1673;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1673_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1673_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1673_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1673_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1673_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1673_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1673_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1673_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1673_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1673_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1673_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1673_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1673_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1673_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1674(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 28,110,124,65,116,87,93,77,51,43,61,24,50,117,100,81,66,53,76,105,21,120,74,4,72,31,16,6,3,59,2,63,10,19,69,33,38,39,115,15,85,126,75,82,45,48,94,56,58,37,88,46,9,113,106,30,18,98,22,91,62,36,83,118,71,86,41,44,25,11,95,103,7,40,80,89,34,114,127,26,52,57,67,5,14,23,79,64,107,73,112,96,20,125,119,121,13,17,90,27,12,68,92,123,55,128,60,97,0,47,111,108,1,49,42,101,122,84,8,54,78,29,102,109,104,70,35,32,99 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_voter_base_key_can_authorize_new_voter";
  test.test_nonce  = 61;
  test.test_number = 1674;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1674_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1674_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1674_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1674_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1674_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1674_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1674_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1674_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1674_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1674_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1674_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1674_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1674_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1674_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
