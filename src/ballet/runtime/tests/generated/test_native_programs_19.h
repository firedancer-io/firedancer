#include "../fd_tests.h"
int test_475(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,89,29,78,103,108,126,121,114,110,92,82,118,33,2,90,76,15,27,125,24,56,80,112,61,30,83,122,79,127,87,26,117,62,55,77,116,123,109,75,111,120,113,98,105,124,106 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_self_fails::old_behavior";
  test.test_nonce  = 34;
  test.test_number = 475;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BYArvmZUTiGLgzMKwJ4nTiYZTAWPoQfJaS8KV4RRHV12",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_475_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_475_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_475_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_475_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Db6zxYmquZxVw9f838TwqRfchAvrLxAUkRDA1Vw2d7Vr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_475_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_475_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_475_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_475_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_475_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_475_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_475_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_475_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_475_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_475_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_475_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_475_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_475_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_475_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_476(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 463;
  test.test_number = 476;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "58EtNr4qAdfuFKgpZYcfwQYs1BzvA7kxwU3sFia1GYHA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HtEJGgJyikjjyKMgrXesvjveJTMZE6G8QLXn9fu4FwvY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4J8ZKFmvrXcDqWUputgdcZ5ERkFdZnt98GGwX9H9S1ob",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_476_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_476_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_476_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_476_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_476_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_476_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_477(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 526;
  test.test_number = 477;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "58EtNr4qAdfuFKgpZYcfwQYs1BzvA7kxwU3sFia1GYHA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HtEJGgJyikjjyKMgrXesvjveJTMZE6G8QLXn9fu4FwvY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4J8ZKFmvrXcDqWUputgdcZ5ERkFdZnt98GGwX9H9S1ob",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_477_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_477_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_477_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_477_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_477_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_477_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_478(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 70;
  test.test_number = 478;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "58EtNr4qAdfuFKgpZYcfwQYs1BzvA7kxwU3sFia1GYHA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HtEJGgJyikjjyKMgrXesvjveJTMZE6G8QLXn9fu4FwvY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5za5Ry6zMrPPDTpgWGH67p1iunW3bGfPAyo7UrSnKvFH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4J8ZKFmvrXcDqWUputgdcZ5ERkFdZnt98GGwX9H9S1ob",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_478_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_478_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_478_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_478_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_478_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_478_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_479(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 428;
  test.test_number = 479;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AcgAWFngnhoian438YxfWfr7XNxHii9ncQzrPw85uwCS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "81zURZYti1gihNEjbPSwokwfMXj69AEa6BVFCCNVBdzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FZXNxx3Sb5LyXPnn7suXreBehuCaN7yZpNHDj7JdBJyy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_479_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_479_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_479_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_479_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_479_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_479_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_480(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 509;
  test.test_number = 480;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AcgAWFngnhoian438YxfWfr7XNxHii9ncQzrPw85uwCS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "81zURZYti1gihNEjbPSwokwfMXj69AEa6BVFCCNVBdzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FZXNxx3Sb5LyXPnn7suXreBehuCaN7yZpNHDj7JdBJyy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_480_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_480_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_480_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_480_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_480_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_480_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_481(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 57;
  test.test_number = 481;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AcgAWFngnhoian438YxfWfr7XNxHii9ncQzrPw85uwCS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "81zURZYti1gihNEjbPSwokwfMXj69AEa6BVFCCNVBdzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9GZSBCV4Q8NJvRARpkmjfS4GWgxk9yoyUPM3ecDbiRLm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FZXNxx3Sb5LyXPnn7suXreBehuCaN7yZpNHDj7JdBJyy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_481_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_481_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_481_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_481_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_481_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_481_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_482(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 414;
  test.test_number = 482;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "58EtNr4qAdfuFKgpZYcfwQYs1BzvA7kxwU3sFia1GYHA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HtEJGgJyikjjyKMgrXesvjveJTMZE6G8QLXn9fu4FwvY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4J8ZKFmvrXcDqWUputgdcZ5ERkFdZnt98GGwX9H9S1ob",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_482_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_482_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_482_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_482_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_482_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_482_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_483(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 382;
  test.test_number = 483;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AcgAWFngnhoian438YxfWfr7XNxHii9ncQzrPw85uwCS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "81zURZYti1gihNEjbPSwokwfMXj69AEa6BVFCCNVBdzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FZXNxx3Sb5LyXPnn7suXreBehuCaN7yZpNHDj7JdBJyy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_483_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_483_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_483_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_483_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_483_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_483_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_484(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 367;
  test.test_number = 484;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "58EtNr4qAdfuFKgpZYcfwQYs1BzvA7kxwU3sFia1GYHA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HtEJGgJyikjjyKMgrXesvjveJTMZE6G8QLXn9fu4FwvY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4J8ZKFmvrXcDqWUputgdcZ5ERkFdZnt98GGwX9H9S1ob",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_484_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_484_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_484_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_484_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_484_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_484_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_485(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 500;
  test.test_number = 485;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "58EtNr4qAdfuFKgpZYcfwQYs1BzvA7kxwU3sFia1GYHA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HtEJGgJyikjjyKMgrXesvjveJTMZE6G8QLXn9fu4FwvY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4J8ZKFmvrXcDqWUputgdcZ5ERkFdZnt98GGwX9H9S1ob",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_485_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_485_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_485_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_485_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_485_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_485_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_486(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 339;
  test.test_number = 486;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AcgAWFngnhoian438YxfWfr7XNxHii9ncQzrPw85uwCS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "81zURZYti1gihNEjbPSwokwfMXj69AEa6BVFCCNVBdzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FZXNxx3Sb5LyXPnn7suXreBehuCaN7yZpNHDj7JdBJyy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_486_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_486_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_486_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_486_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_486_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_486_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_487(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,90,114,89,128,79,27,105,121,61,2,75,15,55,122,111,109,125,106,83,62,103,33,110,108,112,116,77,124,78,126,92,24,76,117,98,56,120,26,30,127,82,123,80,113,87,118 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::new_behavior";
  test.test_nonce  = 468;
  test.test_number = 487;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AcgAWFngnhoian438YxfWfr7XNxHii9ncQzrPw85uwCS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "81zURZYti1gihNEjbPSwokwfMXj69AEa6BVFCCNVBdzP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FZXNxx3Sb5LyXPnn7suXreBehuCaN7yZpNHDj7JdBJyy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_487_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_487_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_487_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_487_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_487_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_487_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_488(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 437;
  test.test_number = 488;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAA46hTe8feXhEp9NhVBUDzhRoC6yn1hZEyzijnALDCG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3vaNq6KkCeZhcuRVjiGD6eZnVaPguj4dcChCxQCQKzRa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4NGbDpVKHi9m497U1AtYgqQwxULWzU3c4DaYfnrxtU4U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_488_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_488_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_488_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_488_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_488_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_488_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_489(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 517;
  test.test_number = 489;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAA46hTe8feXhEp9NhVBUDzhRoC6yn1hZEyzijnALDCG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3vaNq6KkCeZhcuRVjiGD6eZnVaPguj4dcChCxQCQKzRa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4NGbDpVKHi9m497U1AtYgqQwxULWzU3c4DaYfnrxtU4U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_489_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_489_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_489_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_489_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_489_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_489_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_490(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 63;
  test.test_number = 490;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAA46hTe8feXhEp9NhVBUDzhRoC6yn1hZEyzijnALDCG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3vaNq6KkCeZhcuRVjiGD6eZnVaPguj4dcChCxQCQKzRa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FUrvEMDMBVwjHQQUgB9iZE8nigFKVFqGuonQvX5L7G1o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4NGbDpVKHi9m497U1AtYgqQwxULWzU3c4DaYfnrxtU4U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_490_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_490_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_490_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_490_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_490_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_490_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_491(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 423;
  test.test_number = 491;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tZJnxkLqVNaN9Gmxu4ufTfXfhNNyzAuGyMs55J9zSk8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EtQ6adjzvVubiS7KR9qFvrb1EmKDJVzzstoRRwvm9VxQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47aoFsQJExxunPJz69G1cKmkhuHvWoHTmThyTrGk5Wcz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_491_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_491_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_491_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_491_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_491_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_491_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_492(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 496;
  test.test_number = 492;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tZJnxkLqVNaN9Gmxu4ufTfXfhNNyzAuGyMs55J9zSk8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EtQ6adjzvVubiS7KR9qFvrb1EmKDJVzzstoRRwvm9VxQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47aoFsQJExxunPJz69G1cKmkhuHvWoHTmThyTrGk5Wcz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_492_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_492_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_492_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_492_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_492_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_492_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_493(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 71;
  test.test_number = 493;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tZJnxkLqVNaN9Gmxu4ufTfXfhNNyzAuGyMs55J9zSk8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EtQ6adjzvVubiS7KR9qFvrb1EmKDJVzzstoRRwvm9VxQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FUpdzdeSLNxVdJkgJr7FhXidnasKvztyyLwTYdTfWmyB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47aoFsQJExxunPJz69G1cKmkhuHvWoHTmThyTrGk5Wcz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_493_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_493_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_493_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_493_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_493_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_493_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_494(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 393;
  test.test_number = 494;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAA46hTe8feXhEp9NhVBUDzhRoC6yn1hZEyzijnALDCG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3vaNq6KkCeZhcuRVjiGD6eZnVaPguj4dcChCxQCQKzRa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4NGbDpVKHi9m497U1AtYgqQwxULWzU3c4DaYfnrxtU4U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_494_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_494_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_494_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_494_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_494_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_494_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_495(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 383;
  test.test_number = 495;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tZJnxkLqVNaN9Gmxu4ufTfXfhNNyzAuGyMs55J9zSk8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EtQ6adjzvVubiS7KR9qFvrb1EmKDJVzzstoRRwvm9VxQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47aoFsQJExxunPJz69G1cKmkhuHvWoHTmThyTrGk5Wcz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_495_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_495_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_495_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_495_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_495_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_495_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_496(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 347;
  test.test_number = 496;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAA46hTe8feXhEp9NhVBUDzhRoC6yn1hZEyzijnALDCG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3vaNq6KkCeZhcuRVjiGD6eZnVaPguj4dcChCxQCQKzRa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4NGbDpVKHi9m497U1AtYgqQwxULWzU3c4DaYfnrxtU4U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_496_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_496_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_496_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_496_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_496_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_496_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_497(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 475;
  test.test_number = 497;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAA46hTe8feXhEp9NhVBUDzhRoC6yn1hZEyzijnALDCG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3vaNq6KkCeZhcuRVjiGD6eZnVaPguj4dcChCxQCQKzRa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4NGbDpVKHi9m497U1AtYgqQwxULWzU3c4DaYfnrxtU4U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_497_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_497_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_497_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_497_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_497_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_497_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_498(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 328;
  test.test_number = 498;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tZJnxkLqVNaN9Gmxu4ufTfXfhNNyzAuGyMs55J9zSk8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EtQ6adjzvVubiS7KR9qFvrb1EmKDJVzzstoRRwvm9VxQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47aoFsQJExxunPJz69G1cKmkhuHvWoHTmThyTrGk5Wcz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_498_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_498_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_498_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_498_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_498_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_498_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_499(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate_consider_balance_changes::old_behavior";
  test.test_nonce  = 468;
  test.test_number = 499;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6tZJnxkLqVNaN9Gmxu4ufTfXfhNNyzAuGyMs55J9zSk8",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2123495001UL;
  test_acc->result_lamports = 2123495001UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EtQ6adjzvVubiS7KR9qFvrb1EmKDJVzzstoRRwvm9VxQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "47aoFsQJExxunPJz69G1cKmkhuHvWoHTmThyTrGk5Wcz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_499_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_499_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_499_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_499_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_499_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_499_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
