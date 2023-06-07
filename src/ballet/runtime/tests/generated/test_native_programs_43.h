#include "../fd_tests.h"
int test_1075(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 411;
  test.test_number = 1075;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1075_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1075_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1075_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1075_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1075_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1075_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1075_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1075_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1075_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1075_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1075_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1075_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1075_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1075_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1076(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 435;
  test.test_number = 1076;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072707268735UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1076_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1076_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1076_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1076_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1076_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1076_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1076_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1076_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1076_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1076_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1076_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1076_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1076_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1076_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1077(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 402;
  test.test_number = 1077;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072707268735UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1077_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1077_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1077_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1077_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1077_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1077_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1077_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1077_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1077_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1077_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1077_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1077_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1077_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1077_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1078(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 339;
  test.test_number = 1078;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744072709551616UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1078_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1078_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1078_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1078_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1078_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1078_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1078_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1078_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1078_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1078_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1078_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1078_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1078_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1078_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1079(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 2,76,121,114,106,24,109,98,75,122,125,123,62,111,105,61,116,124,90,15,30,80,127,120,83,113,26,78,77,118,126,92,29,89,128,110,56,103,87,79,112,108,117,27,55,82,33 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 349;
  test.test_number = 1079;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1079_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1079_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1079_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1079_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ZbNrko9LWcXyF7J1yyypHA3iyrsQayFUcw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1079_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1079_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1079_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1079_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1079_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1079_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1079_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1079_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1079_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1079_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1080(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 241;
  test.test_number = 1080;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1080_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1080_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1080_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1080_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1080_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1080_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1080_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1080_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1080_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1080_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1080_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1080_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1080_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1080_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1081(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 340;
  test.test_number = 1081;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1081_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1081_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1081_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1081_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1081_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1081_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1081_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1081_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1081_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1081_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1081_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1081_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1081_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1081_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1082(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 207;
  test.test_number = 1082;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1082_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1082_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1082_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1082_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1082_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1082_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1082_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1082_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1082_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1082_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1082_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1082_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1082_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1082_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1083(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 343;
  test.test_number = 1083;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1083_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1083_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1083_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1083_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1083_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1083_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1083_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1083_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1083_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1083_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1083_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1083_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1083_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1083_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1084(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 291;
  test.test_number = 1084;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1084_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1084_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1084_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1084_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282882UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1084_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1084_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1084_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1084_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1084_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1084_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1084_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1084_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1084_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1084_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1085(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 309;
  test.test_number = 1085;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1085_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1085_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1085_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1085_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1085_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1085_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1085_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1085_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1085_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1085_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1085_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1085_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1085_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1085_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1086(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 312;
  test.test_number = 1086;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1086_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1086_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1086_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1086_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1086_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1086_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1086_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1086_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1086_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1086_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1086_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1086_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1086_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1086_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1087(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 327;
  test.test_number = 1087;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1087_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1087_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1087_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1087_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1087_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1087_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1087_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1087_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1087_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1087_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1087_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1087_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1087_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1087_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1088(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 360;
  test.test_number = 1088;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1088_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1088_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1088_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1088_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1088_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1088_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1088_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1088_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1088_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1088_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1088_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1088_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1088_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1088_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1089(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 243;
  test.test_number = 1089;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1089_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1089_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1089_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1089_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282882UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1089_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1089_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1089_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1089_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1089_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1089_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1089_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1089_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1089_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1089_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1090(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 272;
  test.test_number = 1090;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1090_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1090_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1090_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1090_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1090_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1090_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1090_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1090_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1090_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1090_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1090_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1090_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1090_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1090_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1091(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 291;
  test.test_number = 1091;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1091_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1091_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1091_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1091_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1091_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1091_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1091_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1091_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1091_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1091_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1091_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1091_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1091_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1091_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1092(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 309;
  test.test_number = 1092;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1092_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1092_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1092_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1092_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1092_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1092_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1092_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1092_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1092_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1092_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1092_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1092_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1092_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1092_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1093(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 376;
  test.test_number = 1093;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1093_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1093_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1093_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1093_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1093_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1093_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1093_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1093_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1093_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1093_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1093_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1093_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1093_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1093_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1094(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 348;
  test.test_number = 1094;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551613UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1094_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1094_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1094_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1094_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1094_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1094_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1094_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1094_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1094_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1094_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1094_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1094_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1094_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1094_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1095(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 360;
  test.test_number = 1095;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551613UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1095_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1095_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1095_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1095_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1095_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1095_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1095_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1095_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1095_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1095_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1095_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1095_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1095_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1095_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1096(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 379;
  test.test_number = 1096;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1096_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1096_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1096_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1096_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1096_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1096_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1096_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1096_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1096_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1096_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1096_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1096_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1096_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1096_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1097(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,89,82,125,2,15,90,56,103,79,55,120,122,98,61,110,118,117,87,30,26,29,62,123,113,126,111,106,27,108,78,121,116,76,114,109,92,80,75,33,124,24,105,128,77,127,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 416;
  test.test_number = 1097;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1097_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1097_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1097_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1097_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1097_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1097_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1097_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1097_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1097_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1097_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1097_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1097_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1097_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1097_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1098(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 371;
  test.test_number = 1098;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268735UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1098_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1098_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1098_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1098_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1098_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1098_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1098_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1098_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1098_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1098_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1098_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1098_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1098_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1098_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1099(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_staked_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 403;
  test.test_number = 1099;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111YPN3oUFUP59LnoskuiyrpnEN6M6aTGVyfu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1099_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1099_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1099_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1099_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1099_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1099_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1099_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1099_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1099_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1099_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1099_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1099_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1099_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1099_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
