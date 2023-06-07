#include "../fd_tests.h"
int test_525(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 576;
  test.test_number = 525;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_525_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_525_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_525_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_525_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_525_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_525_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_525_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_525_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_525_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_525_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_525_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_525_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_525_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_525_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_525_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_525_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_525_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_525_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_525_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_525_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_525_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_525_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_526(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 577;
  test.test_number = 526;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_526_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_526_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_526_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_526_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_526_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_526_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_526_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_526_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_526_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_526_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_526_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_526_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_526_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_526_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_526_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_526_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_526_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_526_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_526_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_526_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_526_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_526_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_527(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 580;
  test.test_number = 527;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_527_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_527_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_527_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_527_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_527_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_527_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_527_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_527_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_527_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_527_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_527_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_527_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_527_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_527_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_527_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_527_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_527_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_527_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_527_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_527_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_527_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_527_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_528(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 581;
  test.test_number = 528;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_528_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_528_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_528_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_528_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_528_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_528_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_528_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_528_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_528_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_528_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_528_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_528_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_528_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_528_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_528_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_528_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_528_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_528_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_528_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_528_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_528_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_528_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_529(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 586;
  test.test_number = 529;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_529_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_529_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_529_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_529_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_529_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_529_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_529_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_529_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_529_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_529_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_529_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_529_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_529_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_529_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_529_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_529_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_529_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_529_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_529_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_529_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_529_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_529_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_530(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 587;
  test.test_number = 530;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_530_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_530_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_530_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_530_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_530_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_530_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_530_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_530_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_530_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_530_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_530_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_530_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_530_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_530_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_530_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_530_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_530_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_530_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_530_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_530_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_530_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_530_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_531(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 589;
  test.test_number = 531;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565759UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_531_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_531_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_531_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_531_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_531_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_531_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_531_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_531_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_531_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_531_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_531_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_531_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_531_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_531_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_531_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_531_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_531_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_531_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_531_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_531_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_531_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_531_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_532(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 592;
  test.test_number = 532;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_532_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_532_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_532_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_532_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_532_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_532_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_532_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_532_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_532_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_532_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_532_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_532_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_532_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_532_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_532_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_532_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_532_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_532_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_532_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_532_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_532_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_532_raw_sz;
  test.expected_result = -26;
  test.custom_err = 14;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_533(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 592;
  test.test_number = 533;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_533_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_533_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_533_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_533_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_533_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_533_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_533_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_533_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_533_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_533_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_533_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_533_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_533_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_533_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_533_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_533_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_533_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_533_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_533_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_533_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_533_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_533_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_534(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 597;
  test.test_number = 534;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_534_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_534_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_534_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_534_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_534_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_534_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_534_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_534_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_534_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_534_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_534_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_534_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_534_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_534_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_534_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_534_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_534_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_534_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_534_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_534_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_534_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_534_raw_sz;
  test.expected_result = -26;
  test.custom_err = 13;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_535(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 600;
  test.test_number = 535;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565759UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_535_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_535_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_535_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_535_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_535_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_535_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_535_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_535_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_535_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_535_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_535_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_535_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_535_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_535_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_535_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_535_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_535_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_535_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_535_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_535_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_535_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_535_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_536(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 606;
  test.test_number = 536;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_536_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_536_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_536_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_536_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_536_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_536_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_536_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_536_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_536_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_536_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_536_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_536_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_536_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_536_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_536_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_536_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_536_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_536_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_536_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_536_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_536_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_536_raw_sz;
  test.expected_result = -26;
  test.custom_err = 14;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_537(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 89;
  test.test_number = 537;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_537_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_537_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_537_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_537_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_537_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_537_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_537_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_537_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_537_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_537_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_537_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_537_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_537_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_537_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_537_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_537_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_537_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_537_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_537_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_537_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_537_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_537_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_538(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 139;
  test.test_number = 538;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_538_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_538_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_538_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_538_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_538_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_538_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_538_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_538_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_538_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_538_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_538_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_538_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_538_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_538_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_538_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_538_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_538_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_538_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_538_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_538_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_538_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_538_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_538_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_538_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_538_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_538_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_539(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 242;
  test.test_number = 539;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_539_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_539_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_539_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_539_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_539_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_539_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_539_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_539_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_539_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_539_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_539_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_539_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_539_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_539_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_539_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_539_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_539_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_539_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_539_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_539_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_539_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_539_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_539_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_539_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_539_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_539_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_540(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 320;
  test.test_number = 540;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_540_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_540_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_540_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_540_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_540_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_540_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_540_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_540_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_540_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_540_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_540_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_540_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_540_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_540_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_540_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_540_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_540_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_540_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_540_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_540_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_540_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_540_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_540_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_540_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_540_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_540_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_541(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 384;
  test.test_number = 541;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_541_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_541_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_541_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_541_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_541_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_541_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_541_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_541_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_541_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_541_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_541_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_541_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_541_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_541_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_541_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_541_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_541_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_541_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_541_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_541_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_541_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_541_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_541_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_541_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_541_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_541_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_542(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 384;
  test.test_number = 542;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_542_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_542_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_542_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_542_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_542_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_542_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_542_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_542_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_542_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_542_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_542_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_542_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_542_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_542_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_542_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_542_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_542_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_542_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_542_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_542_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_542_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_542_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_542_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_542_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_542_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_542_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_543(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 443;
  test.test_number = 543;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_543_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_543_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_543_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_543_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_543_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_543_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_543_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_543_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_543_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_543_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_543_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_543_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_543_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_543_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_543_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_543_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_543_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_543_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_543_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_543_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_543_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_543_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_543_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_543_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_543_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_543_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_544(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 445;
  test.test_number = 544;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_544_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_544_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_544_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_544_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_544_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_544_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_544_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_544_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_544_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_544_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_544_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_544_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_544_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_544_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_544_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_544_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_544_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_544_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_544_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_544_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_544_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_544_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_544_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_544_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_544_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_544_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_545(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 488;
  test.test_number = 545;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_545_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_545_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_545_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_545_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115q4EpJaTXAZWpCg3J2zppWGSZ46KXozzo9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_545_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_545_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_545_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_545_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_545_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_545_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_545_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_545_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_545_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_545_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_545_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_545_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_545_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_545_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_545_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_545_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_545_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_545_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_545_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_545_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_545_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_545_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_546(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 139;
  test.test_number = 546;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_546_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_546_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_546_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_546_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_546_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_546_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_546_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_546_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_546_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_546_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_546_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_546_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_546_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_546_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_546_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_546_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_546_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_546_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_546_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_546_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_546_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_546_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_547(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 25;
  test.test_number = 547;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_547_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_547_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_547_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_547_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_547_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_547_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_547_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_547_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_547_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_547_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_547_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_547_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_547_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_547_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_547_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_547_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Af7Udc9v3L82dQM5b4zee1Xt77Be4czzbH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_547_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_547_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_547_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_547_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_547_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_547_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_548(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 491;
  test.test_number = 548;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_548_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_548_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_548_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_548_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 2282923UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_548_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_548_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_548_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_548_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_548_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_548_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_548_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_548_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_548_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_548_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_548_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_548_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_548_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_548_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_548_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_548_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_548_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_548_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_549(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::old_behavior";
  test.test_nonce  = 508;
  test.test_number = 549;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111116djSnXB2wXVGT4xDLsfTnkp1p4cCxHAfRq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565803UL;
  test_acc->result_lamports = 2282922UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_549_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_549_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_549_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_549_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_549_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_549_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_549_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_549_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111116EPqoQskEM2Pddp8KTL9JdYEBZMGF3aq7V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_549_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_549_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_549_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_549_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_549_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_549_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_549_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_549_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111115RidqCHAoz6dzmXxGcfWLNzevYqNpaRAUo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_549_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_549_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_549_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_549_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_549_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_549_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
