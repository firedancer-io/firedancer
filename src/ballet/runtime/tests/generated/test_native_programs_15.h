#include "../fd_tests.h"
int test_375(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,120,103,87,26,24,108,112,33,117,98,122,111,76,79,75,92,126,127,30,113,80,106,118,61,123,109,27,125,89,128,121,62,82,2,114,78,83,105,29,116,55,15,90,110,124,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_fake_stake_source::old_behavior";
  test.test_nonce  = 28;
  test.test_number = 375;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7B4muX5nfMM2LhzH8YpEaJvz22w1cmVvRQTxCFdVqvHS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_375_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_375_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_375_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_375_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2xYCkwj7RTZpVszVR1HC3AHG4NcwfYs54wC112bGXCpa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "HV4a7yg87Q25brr68kYSee9GZyNeMR4Uu6WnjLXUdmZc",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_375_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_375_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_375_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_375_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2GA258ZWuB8iCdwMy4chcVGdRf8GgZ8bPSngQC8ebS6q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_375_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_375_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_375_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_375_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_375_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_375_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_375_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_375_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_375_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_375_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_375_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_375_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_375_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_375_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_376(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 285;
  test.test_number = 376;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_376_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_376_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_376_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_376_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_376_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_376_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_376_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_376_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_376_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_376_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_376_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_376_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_376_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_376_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_376_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_376_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_376_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_376_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_376_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_376_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_376_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_376_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_376_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_376_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_376_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_376_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_377(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 30;
  test.test_number = 377;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_377_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_377_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_377_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_377_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_377_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_377_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_377_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_377_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_377_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_377_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_377_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_377_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_377_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_377_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_377_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_377_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_377_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_377_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_377_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_377_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_377_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_377_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_377_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_377_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_377_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_377_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_378(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 372;
  test.test_number = 378;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_378_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_378_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_378_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_378_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_378_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_378_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_378_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_378_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_378_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_378_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_378_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_378_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_378_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_378_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_378_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_378_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_378_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_378_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_378_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_378_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_378_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_378_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_378_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_378_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_378_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_378_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_379(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 421;
  test.test_number = 379;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_379_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_379_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_379_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_379_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_379_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_379_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_379_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_379_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_379_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_379_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_379_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_379_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_379_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_379_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_379_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_379_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_379_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_379_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_379_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_379_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_379_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_379_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_379_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_379_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_379_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_379_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_380(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 483;
  test.test_number = 380;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_380_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_380_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_380_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_380_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_380_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_380_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_380_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_380_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_380_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_380_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_380_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_380_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_380_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_380_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_380_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_380_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_380_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_380_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_380_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_380_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_380_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_380_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_380_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_380_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_380_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_380_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_381(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 514;
  test.test_number = 381;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_381_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_381_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_381_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_381_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_381_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_381_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_381_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_381_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_381_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_381_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_381_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_381_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_381_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_381_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_381_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_381_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_381_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_381_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_381_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_381_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_381_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_381_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_381_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_381_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_381_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_381_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_382(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 544;
  test.test_number = 382;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_382_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_382_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_382_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_382_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_382_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_382_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_382_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_382_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_382_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_382_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_382_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_382_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_382_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_382_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_382_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_382_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_382_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_382_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_382_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_382_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_382_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_382_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_382_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_382_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_382_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_382_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_383(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 570;
  test.test_number = 383;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "39ZsXuVa47gno5d8o1enK2RxPMK84x1bjGuHgY289krz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_383_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_383_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_383_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_383_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BdFNH4EHSBA2Hyhb813TGFbyTKDMGLbSwhHQQgT4c6Td",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_383_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_383_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_383_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_383_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7Q9iHNsc9PU1y28q9VKT21ezryF83zZrxtZb1mTHw5cV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_383_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_383_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_383_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_383_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "JCP18oguA4DsxxReZg6Fb96RbSZXw61dtUwfgFm7Grsr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_383_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_383_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_383_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_383_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_383_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_383_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_383_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_383_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_383_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_383_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_383_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_383_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_383_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_383_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_384(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 280;
  test.test_number = 384;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_384_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_384_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_384_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_384_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_384_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_384_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_384_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_384_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_384_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_384_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_384_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_384_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_384_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_384_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_384_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_384_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_384_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_384_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_384_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_384_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_384_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_384_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_384_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_384_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_384_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_384_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_385(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 33;
  test.test_number = 385;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_385_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_385_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_385_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_385_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_385_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_385_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_385_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_385_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_385_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_385_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_385_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_385_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_385_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_385_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_385_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_385_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_385_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_385_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_385_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_385_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_385_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_385_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_385_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_385_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_385_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_385_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_386(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 370;
  test.test_number = 386;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_386_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_386_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_386_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_386_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_386_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_386_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_386_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_386_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_386_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_386_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_386_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_386_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_386_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_386_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_386_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_386_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_386_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_386_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_386_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_386_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_386_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_386_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_386_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_386_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_386_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_386_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_387(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 421;
  test.test_number = 387;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_387_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_387_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_387_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_387_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_387_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_387_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_387_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_387_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_387_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_387_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_387_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_387_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_387_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_387_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_387_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_387_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_387_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_387_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_387_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_387_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_387_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_387_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_387_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_387_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_387_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_387_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_388(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 462;
  test.test_number = 388;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_388_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_388_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_388_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_388_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_388_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_388_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_388_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_388_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_388_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_388_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_388_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_388_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_388_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_388_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_388_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_388_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_388_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_388_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_388_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_388_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_388_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_388_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_388_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_388_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_388_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_388_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_389(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 495;
  test.test_number = 389;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_389_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_389_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_389_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_389_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_389_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_389_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_389_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_389_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_389_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_389_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_389_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_389_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_389_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_389_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_389_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_389_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_389_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_389_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_389_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_389_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_389_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_389_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_389_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_389_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_389_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_389_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_390(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 523;
  test.test_number = 390;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_390_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_390_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_390_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_390_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_390_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_390_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_390_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_390_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_390_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_390_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_390_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_390_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_390_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_390_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_390_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_390_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_390_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_390_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_390_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_390_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_390_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_390_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_390_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_390_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_390_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_390_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_391(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 77,87,29,122,2,92,114,120,30,108,125,126,26,75,116,103,110,61,111,112,117,123,124,24,56,113,105,89,118,82,27,33,98,121,90,76,83,62,78,128,106,109,15,79,80,127,55 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::new_behavior";
  test.test_nonce  = 543;
  test.test_number = 391;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AsSbUDUo5xbpFqCEebEKDEdZqA2hxCB2csTzCtm9i6xc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_391_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_391_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_391_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_391_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SgwnxDnEBKg6yacYCLpWs1bzDoPcK6ycXnnFFvaE3rJ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_391_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_391_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_391_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_391_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6GSdYj8qNKa8L26AGRzLVYDmY3BRmS5UXJfZhNTPTjft",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_391_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_391_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_391_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_391_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3VGm8VESXwnLE3x4untRKGcMnZagML7rFTKLCGANU8Lz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_391_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_391_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_391_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_391_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_391_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_391_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_391_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_391_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_391_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_391_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_391_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_391_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_391_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_391_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_392(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 315;
  test.test_number = 392;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_392_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_392_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_392_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_392_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_392_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_392_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_392_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_392_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_392_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_392_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_392_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_392_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_392_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_392_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_392_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_392_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_392_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_392_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_392_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_392_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_392_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_392_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_392_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_392_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_392_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_392_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_393(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 396;
  test.test_number = 393;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_393_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_393_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_393_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_393_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_393_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_393_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_393_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_393_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_393_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_393_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_393_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_393_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_393_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_393_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_393_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_393_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_393_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_393_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_393_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_393_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_393_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_393_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_393_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_393_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_393_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_393_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_394(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 39;
  test.test_number = 394;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_394_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_394_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_394_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_394_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_394_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_394_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_394_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_394_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_394_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_394_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_394_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_394_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_394_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_394_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_394_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_394_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_394_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_394_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_394_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_394_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_394_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_394_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_394_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_394_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_394_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_394_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_395(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 456;
  test.test_number = 395;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_395_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_395_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_395_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_395_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_395_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_395_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_395_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_395_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_395_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_395_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_395_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_395_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_395_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_395_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_395_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_395_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_395_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_395_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_395_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_395_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_395_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_395_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_395_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_395_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_395_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_395_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_396(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 505;
  test.test_number = 396;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_396_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_396_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_396_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_396_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_396_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_396_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_396_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_396_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_396_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_396_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_396_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_396_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_396_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_396_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_396_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_396_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_396_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_396_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_396_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_396_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_396_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_396_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_396_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_396_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_396_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_396_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_397(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 535;
  test.test_number = 397;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_397_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_397_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_397_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_397_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_397_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_397_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_397_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_397_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_397_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_397_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_397_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_397_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_397_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_397_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_397_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_397_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_397_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_397_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_397_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_397_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_397_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_397_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_397_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_397_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_397_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_397_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_398(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 556;
  test.test_number = 398;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_398_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_398_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_398_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_398_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_398_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_398_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_398_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_398_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_398_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_398_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_398_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_398_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_398_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_398_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_398_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_398_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_398_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_398_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_398_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_398_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_398_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_398_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_398_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_398_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_398_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_398_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_399(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,55,123,61,30,78,111,80,122,127,124,24,77,103,29,82,117,105,90,126,110,114,15,87,120,33,121,2,118,76,109,26,106,62,56,113,125,83,89,27,112,116,79,75,128,98,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_incorrect_authorized_staker::old_behavior";
  test.test_nonce  = 573;
  test.test_number = 399;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HzZpDHkcHdos9GVHoQk2ckXSBVC3ArSVBu9pWt2Ud6he",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_399_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_399_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_399_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_399_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "UNjtjdFcirTt6tzTutUuZ1g5LWAip9VCR4g6Ftd72gR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_399_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_399_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_399_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_399_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6gFUt2u9aeAWxNJCW2FEESUwxdYruofgjt8GzzetueA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_399_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_399_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_399_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_399_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Wz2u74Hdt5q5RRaYVn9GUkSYkjTpTKgVEeZQCpE72eG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_399_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_399_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_399_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_399_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_399_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_399_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_399_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_399_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_399_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_399_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_399_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_399_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_399_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_399_raw_sz;
  test.expected_result = -26;
  test.custom_err = 6;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
