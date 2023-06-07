#include "../fd_tests.h"
int test_700(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 141;
  test.test_number = 700;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_700_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_700_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_700_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_700_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_700_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_700_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_700_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_700_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_700_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_700_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_700_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_700_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_700_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_700_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_701(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 174;
  test.test_number = 701;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_701_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_701_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_701_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_701_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_701_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_701_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_701_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_701_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_701_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_701_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_701_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_701_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_701_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_701_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_702(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 203;
  test.test_number = 702;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_702_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_702_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_702_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_702_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_702_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_702_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_702_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_702_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_702_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_702_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_702_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_702_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_702_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_702_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_703(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 97;
  test.test_number = 703;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_703_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_703_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_703_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_703_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_703_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_703_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_703_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_703_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_703_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_703_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_703_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_703_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_703_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_703_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_704(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 122;
  test.test_number = 704;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_704_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_704_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_704_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_704_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_704_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_704_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_704_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_704_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_704_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_704_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_704_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_704_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_704_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_704_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_705(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 172;
  test.test_number = 705;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_705_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_705_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_705_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_705_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_705_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_705_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_705_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_705_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_705_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_705_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_705_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_705_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_705_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_705_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_706(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 204;
  test.test_number = 706;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_706_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_706_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_706_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_706_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_706_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_706_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_706_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_706_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_706_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_706_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_706_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_706_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_706_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_706_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_707(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 58;
  test.test_number = 707;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "34EqnSHtG7Li4KswcyrcZgGGksv4sacnmPq8ca1CuzAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_707_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_707_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_707_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_707_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DSYuVtwrpPPZDsZ3MDrm8p8znxQVJNUVXLKFyb4HrUPU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_707_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_707_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_707_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_707_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_707_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_707_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_707_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_707_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_707_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_707_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_708(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 129;
  test.test_number = 708;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_708_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_708_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_708_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_708_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_708_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_708_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_708_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_708_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_708_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_708_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_708_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_708_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_708_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_708_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_709(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 161;
  test.test_number = 709;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_709_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_709_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_709_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_709_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_709_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_709_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_709_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_709_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_709_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_709_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_709_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_709_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_709_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_709_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_710(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 185;
  test.test_number = 710;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_710_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_710_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_710_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_710_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_710_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_710_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_710_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_710_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_710_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_710_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_710_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_710_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_710_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_710_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_711(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,26,105,24,110,124,87,90,106,89,30,111,125,29,98,15,123,126,78,108,82,79,109,117,61,122,118,76,116,120,92,113,121,80,114,56,77,33,103,75,62,112,83,55,127,27,128 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::new_behavior";
  test.test_nonce  = 67;
  test.test_number = 711;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9empWhp1mEaJGYhSFUUjERq1TH2tQm3P6WCZxQwkauMm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_711_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_711_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_711_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_711_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "ArC4PUiiTGkcPkUNshie6pkT5PmoGNTHr6zb5ce9g5fQ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_711_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_711_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_711_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_711_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_711_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_711_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_711_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_711_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_711_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_711_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_712(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 112;
  test.test_number = 712;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_712_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_712_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_712_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_712_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_712_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_712_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_712_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_712_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_712_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_712_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_712_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_712_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_712_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_712_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_713(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 144;
  test.test_number = 713;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_713_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_713_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_713_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_713_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_713_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_713_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_713_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_713_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_713_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_713_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_713_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_713_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_713_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_713_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_714(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 163;
  test.test_number = 714;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_714_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_714_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_714_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_714_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_714_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_714_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_714_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_714_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_714_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_714_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_714_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_714_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_714_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_714_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_715(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 83;
  test.test_number = 715;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_715_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_715_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_715_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_715_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_715_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_715_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_715_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_715_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_715_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_715_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_715_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_715_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_715_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_715_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_716(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 101;
  test.test_number = 716;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_716_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_716_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_716_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_716_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_716_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_716_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_716_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_716_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_716_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_716_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_716_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_716_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_716_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_716_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_717(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 179;
  test.test_number = 717;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_717_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_717_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_717_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_717_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_717_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_717_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_717_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_717_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_717_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_717_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_717_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_717_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_717_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_717_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_718(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 246;
  test.test_number = 718;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_718_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_718_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_718_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_718_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_718_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_718_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_718_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_718_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_718_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_718_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_718_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_718_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_718_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_718_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_719(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 286;
  test.test_number = 719;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_719_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_719_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_719_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_719_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_719_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_719_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_719_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_719_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_719_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_719_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_719_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_719_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_719_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_719_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_720(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 136;
  test.test_number = 720;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_720_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_720_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_720_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_720_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978880UL;
  test_acc->result_lamports = 2978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_720_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_720_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_720_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_720_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_720_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_720_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_720_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_720_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_720_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_720_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_721(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 147;
  test.test_number = 721;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_721_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_721_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_721_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_721_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_721_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_721_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_721_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_721_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_721_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_721_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_721_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_721_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_721_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_721_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_722(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 69;
  test.test_number = 722;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_722_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_722_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_722_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_722_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_722_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_722_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_722_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_722_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_722_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_722_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_722_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_722_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_722_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_722_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_723(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 96;
  test.test_number = 723;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5fQGdiqehwZphFRiALpi5QtPkcaBUPZx7kqM3dyjKuzU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_723_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_723_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_723_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_723_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6bjh4mkM7kZjXYxNVEoRJFF64hBZ8kYseFtJCZkX9tzG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_723_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_723_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_723_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_723_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_723_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_723_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_723_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_723_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_723_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_723_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_724(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,27,83,127,125,108,62,82,98,114,106,77,121,124,111,87,26,61,15,123,120,105,78,76,89,109,103,79,112,117,55,29,80,33,30,113,128,75,126,122,24,56,118,2,116,92,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_smaller_sized_account::old_behavior";
  test.test_nonce  = 124;
  test.test_number = 724;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "A6vmuPzHCAF5LmsKHp9wg8ccAtjpm599kJUZNYgYTZyx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2978881UL;
  test_acc->result_lamports = 2978881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_724_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_724_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_724_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_724_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2siPZWqLv9ydLwKaHFEihsjMZSWNFJmGnC38bVeieF13",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_724_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_724_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_724_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_724_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_724_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_724_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_724_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_724_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_724_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_724_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
