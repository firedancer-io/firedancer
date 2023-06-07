#include "../fd_tests.h"
int test_75(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 567;
  test.test_number = 75;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CQ1snf1Pb8mNtae4RMVv5rV3XYfzY21tVfNrHmPY632U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FRB1rbCRMddUpkiSwrKJh2pwcRWc1ekHVDaw2g2d4qeB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7seq324UpZyafB3KuDeJJkyUvbPxus17ULZFV4mR8BMK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AoM3efyU7fxyP5pDFGwoZoJ2aMLLnbzodWCdpDRB8pmh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_75_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_75_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_75_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_75_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_75_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_75_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_76(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 427;
  test.test_number = 76;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8PUYZodzLW1MLXA1MaQDKH6YAZhYt99zby9a5Gy6n5Sd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4Z6tvkTm1DSqDJVLuMtj9FNN2Dw6TyympD3xYVyF83rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "qsh4Zc1dcSDnSCT8C37cJZeJGGqxKqTBxEdd9NNFMeC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "YtAFTTs7wuoU7YNbDpjyWpobk5L7xvtSmHkZCjmjQnc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_76_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_76_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_76_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_76_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_76_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_76_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_77(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,82,118,89,116,92,55,117,109,111,98,76,122,15,120,33,126,29,2,83,90,105,87,106,62,56,124,79,125,80,108,103,26,127,61,110,78,114,30,27,123,112,128,77,75,121,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 386;
  test.test_number = 77;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X7roqtKbUDPkcc5QMmDY7hZ5GRN2biT31T5sFeiSfiH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GimMaoWjGWurc98Fo66a2fWLHL2hq6oGKgsZrTRsA6GR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AqkcY5WAAUvk4hTJxXS9WSnmMCkjqThQ1h11ZMQ4v6wn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "32ravcyFa6CifpMRN1ZmpQXHTzD2Gr9RtaBgPpyamA5H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_77_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_77_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_77_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_77_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_77_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_77_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_78(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 24;
  test.test_number = 78;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8PUYZodzLW1MLXA1MaQDKH6YAZhYt99zby9a5Gy6n5Sd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4Z6tvkTm1DSqDJVLuMtj9FNN2Dw6TyympD3xYVyF83rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "qsh4Zc1dcSDnSCT8C37cJZeJGGqxKqTBxEdd9NNFMeC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "YtAFTTs7wuoU7YNbDpjyWpobk5L7xvtSmHkZCjmjQnc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_78_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_78_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_78_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_78_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_78_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_78_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_79(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 497;
  test.test_number = 79;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8PUYZodzLW1MLXA1MaQDKH6YAZhYt99zby9a5Gy6n5Sd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4Z6tvkTm1DSqDJVLuMtj9FNN2Dw6TyympD3xYVyF83rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "qsh4Zc1dcSDnSCT8C37cJZeJGGqxKqTBxEdd9NNFMeC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "YtAFTTs7wuoU7YNbDpjyWpobk5L7xvtSmHkZCjmjQnc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_79_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_79_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_79_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_79_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_79_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_79_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_80(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 533;
  test.test_number = 80;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8PUYZodzLW1MLXA1MaQDKH6YAZhYt99zby9a5Gy6n5Sd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4Z6tvkTm1DSqDJVLuMtj9FNN2Dw6TyympD3xYVyF83rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "qsh4Zc1dcSDnSCT8C37cJZeJGGqxKqTBxEdd9NNFMeC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "YtAFTTs7wuoU7YNbDpjyWpobk5L7xvtSmHkZCjmjQnc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_80_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_80_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_80_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_80_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_80_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_80_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_81(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,82,118,89,116,92,55,117,109,111,98,76,122,15,120,33,126,29,2,83,90,105,87,106,62,56,124,79,125,80,108,103,26,127,61,110,78,114,30,27,123,112,128,77,75,121,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 36;
  test.test_number = 81;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X7roqtKbUDPkcc5QMmDY7hZ5GRN2biT31T5sFeiSfiH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GimMaoWjGWurc98Fo66a2fWLHL2hq6oGKgsZrTRsA6GR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AqkcY5WAAUvk4hTJxXS9WSnmMCkjqThQ1h11ZMQ4v6wn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "32ravcyFa6CifpMRN1ZmpQXHTzD2Gr9RtaBgPpyamA5H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_81_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_81_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_81_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_81_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_81_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_81_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_82(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,82,118,89,116,92,55,117,109,111,98,76,122,15,120,33,126,29,2,83,90,105,87,106,62,56,124,79,125,80,108,103,26,127,61,110,78,114,30,27,123,112,128,77,75,121,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 470;
  test.test_number = 82;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X7roqtKbUDPkcc5QMmDY7hZ5GRN2biT31T5sFeiSfiH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GimMaoWjGWurc98Fo66a2fWLHL2hq6oGKgsZrTRsA6GR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AqkcY5WAAUvk4hTJxXS9WSnmMCkjqThQ1h11ZMQ4v6wn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "32ravcyFa6CifpMRN1ZmpQXHTzD2Gr9RtaBgPpyamA5H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_82_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_82_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_82_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_82_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_82_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_82_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_83(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,82,118,89,116,92,55,117,109,111,98,76,122,15,120,33,126,29,2,83,90,105,87,106,62,56,124,79,125,80,108,103,26,127,61,110,78,114,30,27,123,112,128,77,75,121,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 522;
  test.test_number = 83;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X7roqtKbUDPkcc5QMmDY7hZ5GRN2biT31T5sFeiSfiH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GimMaoWjGWurc98Fo66a2fWLHL2hq6oGKgsZrTRsA6GR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AqkcY5WAAUvk4hTJxXS9WSnmMCkjqThQ1h11ZMQ4v6wn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "32ravcyFa6CifpMRN1ZmpQXHTzD2Gr9RtaBgPpyamA5H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_83_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_83_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_83_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_83_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_83_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_83_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_84(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 328;
  test.test_number = 84;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8PUYZodzLW1MLXA1MaQDKH6YAZhYt99zby9a5Gy6n5Sd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4Z6tvkTm1DSqDJVLuMtj9FNN2Dw6TyympD3xYVyF83rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "qsh4Zc1dcSDnSCT8C37cJZeJGGqxKqTBxEdd9NNFMeC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "YtAFTTs7wuoU7YNbDpjyWpobk5L7xvtSmHkZCjmjQnc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_84_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_84_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_84_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_84_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_84_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_84_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_85(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 554;
  test.test_number = 85;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8PUYZodzLW1MLXA1MaQDKH6YAZhYt99zby9a5Gy6n5Sd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4Z6tvkTm1DSqDJVLuMtj9FNN2Dw6TyympD3xYVyF83rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "qsh4Zc1dcSDnSCT8C37cJZeJGGqxKqTBxEdd9NNFMeC",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "YtAFTTs7wuoU7YNbDpjyWpobk5L7xvtSmHkZCjmjQnc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_85_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_85_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_85_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_85_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_85_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_85_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_86(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,82,118,89,116,92,55,117,109,111,98,76,122,15,120,33,126,29,2,83,90,105,87,106,62,56,124,79,125,80,108,103,26,127,61,110,78,114,30,27,123,112,128,77,75,121,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 264;
  test.test_number = 86;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X7roqtKbUDPkcc5QMmDY7hZ5GRN2biT31T5sFeiSfiH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GimMaoWjGWurc98Fo66a2fWLHL2hq6oGKgsZrTRsA6GR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AqkcY5WAAUvk4hTJxXS9WSnmMCkjqThQ1h11ZMQ4v6wn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "32ravcyFa6CifpMRN1ZmpQXHTzD2Gr9RtaBgPpyamA5H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_86_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_86_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_86_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_86_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_86_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_86_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_87(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,82,118,89,116,92,55,117,109,111,98,76,122,15,120,33,126,29,2,83,90,105,87,106,62,56,124,79,125,80,108,103,26,127,61,110,78,114,30,27,123,112,128,77,75,121,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::old_behavior";
  test.test_nonce  = 562;
  test.test_number = 87;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7X7roqtKbUDPkcc5QMmDY7hZ5GRN2biT31T5sFeiSfiH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GimMaoWjGWurc98Fo66a2fWLHL2hq6oGKgsZrTRsA6GR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AqkcY5WAAUvk4hTJxXS9WSnmMCkjqThQ1h11ZMQ4v6wn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "32ravcyFa6CifpMRN1ZmpQXHTzD2Gr9RtaBgPpyamA5H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_87_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_87_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_87_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_87_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_87_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_87_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_88(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 375;
  test.test_number = 88;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_88_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_88_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_88_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_88_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_88_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_88_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_88_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_88_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_88_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_88_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_88_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_88_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_88_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_88_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_88_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_88_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_88_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_88_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_88_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_88_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_88_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_88_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_89(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 434;
  test.test_number = 89;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_89_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_89_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_89_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_89_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_89_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_89_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_89_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_89_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_89_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_89_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_89_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_89_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_89_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_89_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_89_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_89_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_89_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_89_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_89_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_89_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_89_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_89_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_90(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 376;
  test.test_number = 90;
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
  test_acc->data            = fd_flamenco_native_prog_test_90_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_90_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_90_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_90_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_90_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_90_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_90_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_90_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_90_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_90_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_90_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_90_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_90_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_90_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_90_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_90_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_90_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_90_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_90_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_90_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_90_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_90_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_91(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 438;
  test.test_number = 91;
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
  test_acc->data            = fd_flamenco_native_prog_test_91_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_91_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_91_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_91_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_91_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_91_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_91_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_91_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_91_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_91_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_91_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_91_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_91_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_91_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_91_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_91_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_91_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_91_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_91_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_91_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_91_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_91_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_92(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 17;
  test.test_number = 92;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_92_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_92_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_92_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_92_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_92_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_92_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_92_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_92_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_92_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_92_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_92_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_92_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_92_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_92_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_92_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_92_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_92_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_92_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_92_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_92_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_92_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_92_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_93(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 205;
  test.test_number = 93;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_93_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_93_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_93_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_93_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_93_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_93_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_93_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_93_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_93_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_93_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_93_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_93_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_93_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_93_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_93_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_93_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_93_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_93_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_93_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_93_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_93_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_93_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_94(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 330;
  test.test_number = 94;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_94_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_94_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_94_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_94_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_94_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_94_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_94_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_94_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_94_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_94_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_94_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_94_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_94_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_94_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_94_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_94_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_94_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_94_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_94_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_94_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_94_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_94_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_95(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 0;
  test.test_number = 95;
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
  test_acc->data            = fd_flamenco_native_prog_test_95_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_95_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_95_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_95_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_95_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_95_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_95_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_95_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_95_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_95_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_95_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_95_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_95_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_95_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_95_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_95_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_95_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_95_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_95_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_95_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_95_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_95_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_96(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 133;
  test.test_number = 96;
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
  test_acc->data            = fd_flamenco_native_prog_test_96_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_96_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_96_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_96_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_96_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_96_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_96_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_96_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_96_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_96_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_96_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_96_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_96_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_96_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_96_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_96_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_96_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_96_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_96_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_96_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_96_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_96_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_97(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 298;
  test.test_number = 97;
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
  test_acc->data            = fd_flamenco_native_prog_test_97_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_97_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_97_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_97_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BomyPTfQy5iKq6Pfn5mhhFKggL2SW7GYg7dyyS8dJF1G",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_97_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_97_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_97_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_97_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ENq3xcfiAERckBGEpu2NFFCcUStTDyMtDBhzjHTBWTiK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_97_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_97_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_97_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_97_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_97_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_97_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_97_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_97_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_97_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_97_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_97_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_97_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_97_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_97_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_98(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 486;
  test.test_number = 98;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_98_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_98_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_98_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_98_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 43UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_98_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_98_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_98_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_98_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_98_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_98_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_98_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_98_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_98_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_98_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_98_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_98_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_98_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_98_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_98_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_98_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_98_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_98_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_99(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 111,62,30,126,77,120,114,87,110,89,83,98,76,33,116,29,127,103,26,15,118,108,79,112,55,121,106,122,92,117,124,75,105,61,125,128,123,2,24,27,113,56,109,82,90,80,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize::new_behavior";
  test.test_nonce  = 524;
  test.test_number = 99;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6hs4NJbURjNgQQSU2Rkj2MWqqMZW9TdNmfZewHA9iCPa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_99_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_99_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_99_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_99_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Buw9oAgVZvKWCCmTmssWxnG5uByzAbjd6hEgF4p33uWW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_99_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_99_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_99_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_99_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DcuXFPSeHU2RP3QUcT2XixfvhvtgmBiA9rfv6TuLG2qq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_99_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_99_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_99_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_99_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_99_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_99_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_99_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_99_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_99_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_99_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_99_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_99_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_99_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_99_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
