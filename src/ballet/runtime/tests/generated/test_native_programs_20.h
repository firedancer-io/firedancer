#include "../fd_tests.h"
int test_500(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 140;
  test.test_number = 500;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_500_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_500_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_500_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_500_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_500_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_500_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_500_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_500_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_500_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_500_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_500_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_500_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_500_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_500_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_500_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_500_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_500_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_500_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_500_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_500_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_500_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_500_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_500_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_500_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_500_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_500_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_501(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 191;
  test.test_number = 501;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_501_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_501_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_501_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_501_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_501_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_501_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_501_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_501_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_501_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_501_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_501_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_501_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_501_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_501_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_501_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_501_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_501_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_501_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_501_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_501_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_501_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_501_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_501_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_501_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_501_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_501_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_502(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 381;
  test.test_number = 502;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_502_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_502_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_502_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_502_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_502_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_502_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_502_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_502_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_502_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_502_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_502_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_502_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_502_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_502_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_502_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_502_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_502_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_502_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_502_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_502_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_502_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_502_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_502_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_502_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_502_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_502_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_503(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 399;
  test.test_number = 503;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_503_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_503_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_503_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_503_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_503_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_503_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_503_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_503_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_503_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_503_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_503_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_503_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_503_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_503_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_503_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_503_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_503_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_503_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_503_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_503_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_503_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_503_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_503_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_503_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_503_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_503_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_504(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 438;
  test.test_number = 504;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_504_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_504_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_504_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_504_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_504_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_504_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_504_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_504_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_504_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_504_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_504_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_504_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_504_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_504_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_504_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_504_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_504_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_504_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_504_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_504_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_504_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_504_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_504_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_504_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_504_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_504_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_505(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 469;
  test.test_number = 505;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_505_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_505_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_505_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_505_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_505_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_505_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_505_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_505_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_505_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_505_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_505_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_505_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_505_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_505_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_505_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_505_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_505_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_505_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_505_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_505_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_505_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_505_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_505_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_505_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_505_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_505_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_506(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 487;
  test.test_number = 506;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565759UL;
  test_acc->result_lamports = 1004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_506_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_506_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_506_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_506_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_506_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_506_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_506_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_506_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_506_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_506_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_506_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_506_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_506_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_506_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_506_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_506_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_506_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_506_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_506_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_506_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_506_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_506_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_506_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_506_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_506_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_506_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_507(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 512;
  test.test_number = 507;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565759UL;
  test_acc->result_lamports = 1004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_507_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_507_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_507_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_507_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117qkFjr4u54stuNNUR8fRF8dNhaP35yvANs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_507_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_507_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_507_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_507_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_507_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_507_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_507_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_507_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_507_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_507_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_507_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_507_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_507_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_507_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_507_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_507_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_507_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_507_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_507_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_507_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_507_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_507_raw_sz;
  test.expected_result = -26;
  test.custom_err = 3;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_508(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 115;
  test.test_number = 508;
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
  test_acc->data            = fd_flamenco_native_prog_test_508_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_508_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_508_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_508_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_508_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_508_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_508_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_508_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_508_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_508_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_508_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_508_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_508_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_508_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_508_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_508_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_508_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_508_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_508_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_508_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_508_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_508_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_509(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 21;
  test.test_number = 509;
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
  test_acc->data            = fd_flamenco_native_prog_test_509_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_509_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_509_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_509_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_509_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_509_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_509_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_509_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_509_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_509_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_509_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_509_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_509_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_509_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_509_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_509_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_509_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_509_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_509_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_509_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_509_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_509_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_510(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 523;
  test.test_number = 510;
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
  test_acc->data            = fd_flamenco_native_prog_test_510_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_510_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_510_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_510_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 1002282922UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_510_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_510_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_510_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_510_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_510_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_510_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_510_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_510_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_510_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_510_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_510_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_510_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_510_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_510_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_510_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_510_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_510_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_510_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_511(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 533;
  test.test_number = 511;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565802UL;
  test_acc->result_lamports = 2282922UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_511_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_511_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_511_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_511_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_511_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_511_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_511_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_511_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_511_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_511_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_511_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_511_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_511_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_511_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_511_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_511_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_511_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_511_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_511_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_511_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_511_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_511_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_512(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 537;
  test.test_number = 512;
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
  test_acc->data            = fd_flamenco_native_prog_test_512_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_512_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_512_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_512_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 1002282922UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_512_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_512_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_512_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_512_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_512_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_512_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_512_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_512_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_512_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_512_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_512_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_512_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_512_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_512_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_512_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_512_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_512_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_512_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_513(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 53;
  test.test_number = 513;
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
  test_acc->data            = fd_flamenco_native_prog_test_513_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_513_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_513_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_513_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_513_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_513_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_513_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_513_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_513_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_513_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_513_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_513_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_513_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_513_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_513_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_513_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111119rSGfPZLcyCGzY4uYEL1fkzJr6fke9qKxb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_513_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_513_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_513_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_513_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_513_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_513_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_514(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 542;
  test.test_number = 514;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111118eRTi4fUVRoeYEeeTyL4DPAwxatvWT5q1Z",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565802UL;
  test_acc->result_lamports = 2282922UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_514_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_514_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_514_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_514_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_514_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_514_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_514_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_514_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_514_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_514_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_514_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_514_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_514_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_514_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_514_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_514_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_514_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_514_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_514_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_514_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_514_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_514_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_515(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 543;
  test.test_number = 515;
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
  test_acc->data            = fd_flamenco_native_prog_test_515_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_515_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_515_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_515_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "111111128b6KVhaxjQXpJej7zPHx3SNEbDzktB5nZD",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_515_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_515_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_515_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_515_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_515_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_515_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_515_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_515_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_515_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_515_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_515_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_515_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_515_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_515_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_515_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_515_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_515_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_515_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_516(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 548;
  test.test_number = 516;
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
  test_acc->data            = fd_flamenco_native_prog_test_516_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_516_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_516_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_516_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111112F2VyFSMa6HwqPaxWP6d3oSipfJ7rFvR7cj",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_516_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_516_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_516_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_516_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_516_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_516_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_516_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_516_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_516_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_516_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_516_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_516_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_516_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_516_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_516_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_516_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_516_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_516_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_517(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 552;
  test.test_number = 517;
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
  test_acc->data            = fd_flamenco_native_prog_test_517_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_517_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_517_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_517_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_517_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_517_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_517_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_517_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_517_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_517_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_517_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_517_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_517_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_517_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_517_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_517_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_517_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_517_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_517_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_517_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_517_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_517_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_518(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 552;
  test.test_number = 518;
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
  test_acc->data            = fd_flamenco_native_prog_test_518_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_518_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_518_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_518_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_518_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_518_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_518_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_518_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_518_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_518_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_518_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_518_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_518_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_518_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_518_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_518_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_518_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_518_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_518_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_518_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_518_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_518_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_519(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 559;
  test.test_number = 519;
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
  test_acc->data            = fd_flamenco_native_prog_test_519_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_519_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_519_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_519_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_519_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_519_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_519_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_519_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_519_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_519_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_519_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_519_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_519_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_519_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_519_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_519_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_519_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_519_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_519_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_519_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_519_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_519_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_520(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 559;
  test.test_number = 520;
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
  test_acc->data            = fd_flamenco_native_prog_test_520_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_520_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_520_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_520_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_520_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_520_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_520_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_520_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_520_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_520_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_520_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_520_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_520_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_520_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_520_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_520_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_520_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_520_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_520_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_520_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_520_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_520_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_521(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 563;
  test.test_number = 521;
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
  test_acc->data            = fd_flamenco_native_prog_test_521_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_521_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_521_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_521_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_521_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_521_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_521_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_521_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_521_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_521_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_521_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_521_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_521_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_521_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_521_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_521_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_521_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_521_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_521_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_521_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_521_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_521_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_522(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 568;
  test.test_number = 522;
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
  test_acc->data            = fd_flamenco_native_prog_test_522_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_522_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_522_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_522_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_522_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_522_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_522_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_522_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_522_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_522_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_522_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_522_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_522_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_522_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_522_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_522_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_522_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_522_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_522_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_522_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_522_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_522_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_523(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 568;
  test.test_number = 523;
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
  test_acc->data            = fd_flamenco_native_prog_test_523_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_523_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_523_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_523_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1004565760UL;
  test_acc->result_lamports = 1004565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_523_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_523_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_523_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_523_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_523_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_523_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_523_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_523_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_523_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_523_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_523_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_523_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_523_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_523_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_523_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_523_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_523_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_523_raw_sz;
  test.expected_result = -9;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_524(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,82,125,76,122,87,116,113,105,127,92,90,2,56,103,61,106,117,55,120,75,78,98,126,111,109,123,114,27,77,80,29,33,24,26,108,89,83,30,121,124,15,62,110,112,118,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_redelegate::new_behavior";
  test.test_nonce  = 572;
  test.test_number = 524;
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
  test_acc->data            = fd_flamenco_native_prog_test_524_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_524_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_524_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_524_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111193m4hAxmCcGXMfnjVPfNhWSjb69sDgffKu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_524_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_524_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_524_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_524_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111118F5rixNBnFLmioWZSYzjjFuAL5dyoDVzhD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_524_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_524_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_524_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_524_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_524_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_524_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_524_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_524_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_524_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_524_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_524_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_524_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_524_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_524_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
