#include "../fd_tests.h"
int test_1700(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,90,30,33,89,117,98,121,116,80,27,109,124,26,92,62,24,55,75,123,128,56,122,76,113,29,111,112,83,15,61,106,105,114,103,87,82,118,108,2,127,77,120,79,78,126,110 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 19;
  test.test_number = 1700;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4H33ARjZqc1U4Av5veoYwfbnA9BAWCxDYFfaeWaeK3ny",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1700_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1700_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1700_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1700_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "87Tjf4iDBhEea6rgGPtPTC5eAVadULdTjWBtywMtGMoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1700_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1700_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1700_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1700_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1700_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1700_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1700_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1700_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1700_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1700_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1700_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1700_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwVKGwovj97ADXhK8zTQ9d4eieyW3P7opDAz2ZHH12vz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1700_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1700_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1700_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1700_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1700_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1700_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1701(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,90,30,33,89,117,98,121,116,80,27,109,124,26,92,62,24,55,75,123,128,56,122,76,113,29,111,112,83,15,61,106,105,114,103,87,82,118,108,2,127,77,120,79,78,126,110 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 33;
  test.test_number = 1701;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4H33ARjZqc1U4Av5veoYwfbnA9BAWCxDYFfaeWaeK3ny",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1701_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1701_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1701_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1701_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "87Tjf4iDBhEea6rgGPtPTC5eAVadULdTjWBtywMtGMoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1701_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1701_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1701_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1701_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1701_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1701_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1701_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1701_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1701_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1701_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1701_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1701_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwVKGwovj97ADXhK8zTQ9d4eieyW3P7opDAz2ZHH12vz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1701_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1701_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1701_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1701_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1701_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1701_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1702(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 120,26,21,106,11,44,58,17,55,2,74,92,20,14,71,1,50,85,32,5,83,24,13,40,110,67,111,124,100,63,54,66,25,121,35,72,69,123,18,47,117,80,105,53,30,64,4,36,115,29,45,95,112,98,37,10,15,114,102,118,41,27,79,39,59,127,128,108,0,57,8,77,33,88,61,86,125,82,96,60,76,6,51,94,81,19,68,49,31,56,9,38,104,43,3,42,34,126,91,22,12,28,65,52,97,90,113,101,87,75,103,89,122,73,93,70,7,48,84,46,78,107,116,99,16,119,62,23,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 79;
  test.test_number = 1702;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AZkz3vMWd2oMPk28CP4Qayn3YF4ZEhzC5NfudkSqAB6T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1702_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1702_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1702_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1702_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Qg6QRRu5EMDgKt7RRET8queCB4qhHYjvtKDF793KDNe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1702_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1702_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1702_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1702_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1702_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1702_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1702_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1702_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1702_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1702_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1702_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1702_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J3hougktvitrEuMdn8gQkotvaqt8NGJSfr1MSbNUfz46",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1702_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1702_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1702_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1702_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1702_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1702_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1703(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 117,1,49,54,128,67,38,3,86,33,108,45,69,26,89,51,41,43,102,95,106,123,97,74,14,114,82,40,119,47,78,39,9,65,11,12,10,62,80,87,27,100,76,101,75,112,34,20,70,84,30,111,2,124,110,120,37,126,16,23,7,19,93,31,99,55,61,42,85,79,116,71,44,25,81,35,73,83,92,68,77,91,17,94,105,57,22,24,60,104,21,36,107,118,122,59,90,8,64,125,13,6,63,46,58,15,109,5,4,121,56,72,32,115,96,88,113,18,66,98,48,29,28,0,103,50,53,52,127 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 74;
  test.test_number = 1703;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4H33ARjZqc1U4Av5veoYwfbnA9BAWCxDYFfaeWaeK3ny",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1703_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1703_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1703_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1703_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "87Tjf4iDBhEea6rgGPtPTC5eAVadULdTjWBtywMtGMoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1703_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1703_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1703_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1703_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1703_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1703_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1703_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1703_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1703_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1703_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1703_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1703_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwVKGwovj97ADXhK8zTQ9d4eieyW3P7opDAz2ZHH12vz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1703_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1703_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1703_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1703_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1703_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1703_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1704(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 76,24,55,124,111,89,118,15,120,103,106,128,87,110,82,121,79,83,2,62,33,27,123,114,90,26,56,122,127,105,113,116,92,78,77,30,75,125,126,80,112,108,109,98,117,29,61 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 64;
  test.test_number = 1704;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AZkz3vMWd2oMPk28CP4Qayn3YF4ZEhzC5NfudkSqAB6T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1704_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1704_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1704_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1704_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Qg6QRRu5EMDgKt7RRET8queCB4qhHYjvtKDF793KDNe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1704_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1704_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1704_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1704_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1704_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1704_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1704_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1704_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1704_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1704_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1704_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1704_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J3hougktvitrEuMdn8gQkotvaqt8NGJSfr1MSbNUfz46",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1704_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1704_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1704_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1704_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1704_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1704_raw_sz;
  test.expected_result = -26;
  test.custom_err = 18;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1705(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 122,11,25,57,106,65,85,91,29,104,39,70,101,128,20,19,112,5,9,96,2,6,127,88,84,45,125,115,13,116,32,89,41,100,81,93,98,18,48,109,52,71,72,74,51,4,26,59,62,47,22,58,35,33,90,78,49,73,16,21,87,92,50,76,36,114,43,31,61,7,55,117,121,60,107,3,30,17,124,95,0,66,102,108,123,12,113,99,54,23,8,86,97,69,44,53,67,38,103,118,68,77,110,28,37,111,46,14,63,80,83,42,40,27,56,126,119,15,1,120,94,10,82,64,34,24,105,75,79 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 76;
  test.test_number = 1705;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AZkz3vMWd2oMPk28CP4Qayn3YF4ZEhzC5NfudkSqAB6T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1705_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1705_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1705_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1705_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Qg6QRRu5EMDgKt7RRET8queCB4qhHYjvtKDF793KDNe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1705_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1705_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1705_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1705_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1705_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1705_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1705_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1705_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1705_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1705_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1705_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1705_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J3hougktvitrEuMdn8gQkotvaqt8NGJSfr1MSbNUfz46",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1705_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1705_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1705_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1705_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1705_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1705_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1706(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 129;
  uchar disabled_features[] = { 47,90,9,66,83,82,106,10,45,13,5,69,4,17,103,108,115,123,125,31,48,126,44,6,99,8,93,26,104,32,30,111,70,91,95,53,15,113,122,75,64,7,55,127,112,16,1,114,20,18,76,84,40,60,86,57,46,97,12,24,124,77,92,3,23,71,118,29,107,110,21,128,19,63,102,117,87,81,43,73,65,98,33,89,54,38,59,68,101,52,25,2,34,61,116,109,67,0,105,11,94,58,56,37,42,119,49,22,62,120,14,36,80,88,27,121,35,79,72,78,100,50,74,51,96,39,41,28,85 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 79;
  test.test_number = 1706;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4H33ARjZqc1U4Av5veoYwfbnA9BAWCxDYFfaeWaeK3ny",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1706_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1706_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1706_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1706_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "87Tjf4iDBhEea6rgGPtPTC5eAVadULdTjWBtywMtGMoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1706_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1706_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1706_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1706_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1706_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1706_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1706_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1706_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1706_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1706_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1706_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1706_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwVKGwovj97ADXhK8zTQ9d4eieyW3P7opDAz2ZHH12vz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1706_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1706_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1706_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1706_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1706_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1706_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1707(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,2,27,127,83,87,116,114,106,124,111,128,56,30,108,15,118,79,105,125,29,110,33,117,75,113,61,78,121,82,98,55,126,123,90,24,77,103,112,120,109,80,26,62,89,76,122 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 48;
  test.test_number = 1707;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "AZkz3vMWd2oMPk28CP4Qayn3YF4ZEhzC5NfudkSqAB6T",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1707_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1707_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1707_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1707_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2Qg6QRRu5EMDgKt7RRET8queCB4qhHYjvtKDF793KDNe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1707_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1707_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1707_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1707_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1707_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1707_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1707_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1707_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1707_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1707_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1707_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1707_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J3hougktvitrEuMdn8gQkotvaqt8NGJSfr1MSbNUfz46",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1707_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1707_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1707_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1707_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1707_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1707_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1708(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,2,27,127,83,87,116,114,106,124,111,128,56,30,108,15,118,79,105,125,29,110,33,117,75,113,61,78,121,82,98,55,126,123,90,24,77,103,112,120,109,80,26,62,89,76,122 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 53;
  test.test_number = 1708;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4H33ARjZqc1U4Av5veoYwfbnA9BAWCxDYFfaeWaeK3ny",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1708_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1708_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1708_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1708_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "87Tjf4iDBhEea6rgGPtPTC5eAVadULdTjWBtywMtGMoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1708_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1708_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1708_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1708_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1708_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1708_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1708_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1708_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1708_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1708_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1708_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1708_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwVKGwovj97ADXhK8zTQ9d4eieyW3P7opDAz2ZHH12vz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1708_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1708_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1708_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1708_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1708_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1708_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1709(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,2,27,127,83,87,116,114,106,124,111,128,56,30,108,15,118,79,105,125,29,110,33,117,75,113,61,78,121,82,98,55,126,123,90,24,77,103,112,120,109,80,26,62,89,76,122 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_state_withdraw";
  test.test_nonce  = 65;
  test.test_number = 1709;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4H33ARjZqc1U4Av5veoYwfbnA9BAWCxDYFfaeWaeK3ny",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1709_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1709_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1709_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1709_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "87Tjf4iDBhEea6rgGPtPTC5eAVadULdTjWBtywMtGMoW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1709_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1709_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1709_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1709_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1709_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1709_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1709_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1709_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1709_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1709_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1709_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1709_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EwVKGwovj97ADXhK8zTQ9d4eieyW3P7opDAz2ZHH12vz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1709_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1709_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1709_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1709_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1709_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1709_raw_sz;
  test.expected_result = -26;
  test.custom_err = 18;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1710(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 98,15,127,106,109,113,128,77,124,120,117,90,125,62,24,79,75,83,112,56,87,30,80,89,29,105,118,33,121,116,110,92,78,76,103,114,55,61,26,123,111,27,108,122,126,2,82 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_commission";
  test.test_nonce  = 24;
  test.test_number = 1710;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3sKbwovebW1ZyDqu9MaZNDRXsgt3QAgERdnCH3aeKU1V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1710_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1710_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1710_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1710_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FYYbENZxxYGjsPFf3SFLdRA5xdwfJy3sT15cQ9bCVWEH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1710_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1710_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1710_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1710_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1710_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1710_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1710_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1710_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1710_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1710_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1710_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1710_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1710_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1710_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1711(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 82,123,121,87,116,109,27,79,92,125,111,117,62,110,108,30,33,2,90,114,106,112,118,75,83,128,122,127,113,124,105,56,26,89,15,61,55,80,77,126,120,29,24,76,78,98,103 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_commission";
  test.test_nonce  = 38;
  test.test_number = 1711;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3sKbwovebW1ZyDqu9MaZNDRXsgt3QAgERdnCH3aeKU1V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1711_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1711_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1711_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1711_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FYYbENZxxYGjsPFf3SFLdRA5xdwfJy3sT15cQ9bCVWEH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1711_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1711_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1711_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1711_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1711_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1711_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1711_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1711_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1711_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1711_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1711_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1711_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1711_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1711_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1712(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,123,121,87,116,109,27,79,92,125,111,117,62,110,108,30,33,2,90,114,106,112,118,75,83,128,122,127,113,124,105,56,26,89,15,61,55,80,77,126,120,29,24,76,78,98,103 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_commission";
  test.test_nonce  = 26;
  test.test_number = 1712;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7iewCaxc5qBqZzjLBqKjdff28rQ2eFHft6fWigZ2dyo5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1712_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1712_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1712_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1712_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6V26Met1AUsj2hwPCEfB2xPGENxjG4UEdfR9ZzNhd42R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1712_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1712_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1712_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1712_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1712_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1712_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1712_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1712_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1712_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1712_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1712_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1712_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1712_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1712_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1713(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 82,123,121,87,116,109,27,79,92,125,111,117,62,110,108,30,33,2,90,114,106,112,118,75,83,128,122,127,113,124,105,56,26,89,15,61,55,80,77,126,120,29,24,76,78,98,103 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_commission";
  test.test_nonce  = 39;
  test.test_number = 1713;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7iewCaxc5qBqZzjLBqKjdff28rQ2eFHft6fWigZ2dyo5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1713_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1713_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1713_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1713_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6V26Met1AUsj2hwPCEfB2xPGENxjG4UEdfR9ZzNhd42R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1713_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1713_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1713_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1713_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1713_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1713_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1713_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1713_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1713_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1713_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1713_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1713_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1713_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1713_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1714(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,87,26,98,78,79,111,123,121,116,118,83,56,120,117,2,76,108,61,114,106,127,92,80,29,110,77,90,109,126,103,55,27,112,30,89,24,125,82,105,33,75,124,15,62,122,128 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_commission";
  test.test_nonce  = 6;
  test.test_number = 1714;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3sKbwovebW1ZyDqu9MaZNDRXsgt3QAgERdnCH3aeKU1V",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1714_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1714_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1714_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1714_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FYYbENZxxYGjsPFf3SFLdRA5xdwfJy3sT15cQ9bCVWEH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1714_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1714_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1714_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1714_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1714_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1714_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1714_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1714_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1714_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1714_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1714_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1714_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1714_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1714_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1715(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,87,26,98,78,79,111,123,121,116,118,83,56,120,117,2,76,108,61,114,106,127,92,80,29,110,77,90,109,126,103,55,27,112,30,89,24,125,82,105,33,75,124,15,62,122,128 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_commission";
  test.test_nonce  = 10;
  test.test_number = 1715;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7iewCaxc5qBqZzjLBqKjdff28rQ2eFHft6fWigZ2dyo5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1715_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1715_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1715_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1715_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6V26Met1AUsj2hwPCEfB2xPGENxjG4UEdfR9ZzNhd42R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1715_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1715_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1715_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1715_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1715_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1715_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1715_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1715_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1715_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1715_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1715_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1715_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1715_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1715_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1716(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,111,33,121,2,118,126,110,90,98,62,125,105,75,127,87,26,56,128,15,24,116,113,78,76,103,61,79,55,108,83,112,106,77,120,114,124,122,82,30,89,92,80,27,117,29,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_validator_identity";
  test.test_nonce  = 37;
  test.test_number = 1716;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1Q5DbzdNPwBmcfTLCALMF15aQN1qoW7Y5yFPCHxxPgd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1716_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1716_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1716_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1716_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmFS8hcLvg2pvmoHpsgUP4Jj142NqDVyU1mESvmXhCYd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1716_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1716_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1716_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1716_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FpLPaQKcwGunFqK8jtii52Km19zeogD4jxMLo7VB6WVs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1716_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1716_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1716_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1716_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1716_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1716_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1717(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,78,110,2,83,114,113,98,30,27,15,56,76,124,62,116,103,92,77,105,127,118,128,24,112,126,123,106,79,117,61,80,125,121,109,122,55,33,108,90,75,111,89,87,26,82,120 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_validator_identity";
  test.test_nonce  = 7;
  test.test_number = 1717;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1Q5DbzdNPwBmcfTLCALMF15aQN1qoW7Y5yFPCHxxPgd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1717_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1717_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1717_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1717_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmFS8hcLvg2pvmoHpsgUP4Jj142NqDVyU1mESvmXhCYd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1717_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1717_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1717_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1717_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FpLPaQKcwGunFqK8jtii52Km19zeogD4jxMLo7VB6WVs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1717_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1717_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1717_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1717_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1717_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1717_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1718(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 117,106,123,2,98,128,105,90,109,110,127,30,82,75,118,62,111,33,15,124,24,113,27,116,76,56,87,61,80,29,89,122,120,78,83,112,26,114,55,77,79,92,126,103,121,125,108 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_validator_identity";
  test.test_nonce  = 23;
  test.test_number = 1718;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1Q5DbzdNPwBmcfTLCALMF15aQN1qoW7Y5yFPCHxxPgd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1718_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1718_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1718_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1718_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FmFS8hcLvg2pvmoHpsgUP4Jj142NqDVyU1mESvmXhCYd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1718_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1718_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1718_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1718_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FpLPaQKcwGunFqK8jtii52Km19zeogD4jxMLo7VB6WVs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1718_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1718_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1718_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1718_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1718_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1718_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1719(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,106,123,2,98,128,105,90,109,110,127,30,82,75,118,62,111,33,15,124,24,113,27,116,76,56,87,61,80,29,89,122,120,78,83,112,26,114,55,77,79,92,126,103,121,125,108 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_validator_identity";
  test.test_nonce  = 25;
  test.test_number = 1719;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GAVV6cNdoxxZt1C1uH5SXFkH7MDSptzaLqoqbXETQS7k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1719_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1719_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1719_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1719_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5ZEnitFzZSckYtkt1HSqsVvwsUukM2PsJfBQzzHkaNYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1719_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1719_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1719_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1719_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7isjVV1i6UYZYBDGyuCox5Vsjz9WWGobUzsTLWSCoRCs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1719_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1719_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1719_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1719_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1719_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1719_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1720(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,106,123,2,98,128,105,90,109,110,127,30,82,75,118,62,111,33,15,124,24,113,27,116,76,56,87,61,80,29,89,122,120,78,83,112,26,114,55,77,79,92,126,103,121,125,108 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_validator_identity";
  test.test_nonce  = 38;
  test.test_number = 1720;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GAVV6cNdoxxZt1C1uH5SXFkH7MDSptzaLqoqbXETQS7k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1720_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1720_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1720_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1720_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5ZEnitFzZSckYtkt1HSqsVvwsUukM2PsJfBQzzHkaNYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1720_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1720_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1720_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1720_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7isjVV1i6UYZYBDGyuCox5Vsjz9WWGobUzsTLWSCoRCs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1720_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1720_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1720_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1720_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1720_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1720_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1721(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,106,123,2,98,128,105,90,109,110,127,30,82,75,118,62,111,33,15,124,24,113,27,116,76,56,87,61,80,29,89,122,120,78,83,112,26,114,55,77,79,92,126,103,121,125,108 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_update_validator_identity";
  test.test_nonce  = 9;
  test.test_number = 1721;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GAVV6cNdoxxZt1C1uH5SXFkH7MDSptzaLqoqbXETQS7k",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1721_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1721_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1721_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1721_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "5ZEnitFzZSckYtkt1HSqsVvwsUukM2PsJfBQzzHkaNYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1721_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1721_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1721_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1721_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7isjVV1i6UYZYBDGyuCox5Vsjz9WWGobUzsTLWSCoRCs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1721_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1721_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1721_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1721_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1721_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1721_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1722(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 117,106,123,2,98,128,105,90,109,110,127,30,82,75,118,62,111,33,15,124,24,113,27,116,76,56,87,61,80,29,89,122,120,78,83,112,26,114,55,77,79,92,126,103,121,125,108 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 14;
  test.test_number = 1722;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GaKyKdk6VewrKiEbgaAFwR2fesBu8Bx2bW5CSwpfD5gD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1722_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1722_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1722_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1722_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1722_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1722_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1722_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1722_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1722_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1722_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1722_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1722_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9oy7bvcoZ4bYL5PUiQ6xGWBTE2exdZjTLhpM23Y1kjZ3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1722_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1722_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1722_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1722_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1722_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1722_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1723(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 87,123,75,126,113,62,118,30,26,27,89,124,24,29,98,83,33,109,76,114,77,112,116,82,120,80,108,127,92,117,78,110,121,2,111,90,55,61,125,15,106,56,103,122,128,79,105 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 10;
  test.test_number = 1723;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2v7ibcAKT78LDQV48eNdxk6WeHdJjSq4QF7e6Ao6T961",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858640UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1723_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1723_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1723_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1723_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1723_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1723_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1723_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1723_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1723_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1723_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1723_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1723_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AgrAibrNFysBYA4e4jkKSB55j6sXx7xtuAiR8vchBRaa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1723_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1723_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1723_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1723_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1723_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1723_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1724(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 123,76,118,80,27,112,124,126,87,125,2,90,61,30,121,83,92,108,33,29,55,24,120,26,128,103,106,82,75,117,127,98,79,114,122,78,111,77,116,109,113,105,89,110,56,62,15 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_withdraw";
  test.test_nonce  = 71;
  test.test_number = 1724;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2v7ibcAKT78LDQV48eNdxk6WeHdJjSq4QF7e6Ao6T961",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 26858640UL;
  test_acc->result_lamports = 26858598UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1724_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1724_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1724_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1724_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1724_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1724_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1724_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1724_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1724_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1724_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1724_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1724_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AgrAibrNFysBYA4e4jkKSB55j6sXx7xtuAiR8vchBRaa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1724_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1724_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1724_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1724_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1724_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1724_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
