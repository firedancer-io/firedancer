#include "../fd_tests.h"
int test_750(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 116;
  test.test_number = 750;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_750_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_750_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_750_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_750_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_750_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_750_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_750_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_750_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_750_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_750_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_750_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_750_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_750_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_750_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_751(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 175;
  test.test_number = 751;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565758UL;
  test_acc->result_lamports = 4565758UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_751_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_751_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_751_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_751_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_751_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_751_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_751_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_751_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_751_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_751_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_751_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_751_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_751_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_751_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_752(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 111;
  test.test_number = 752;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_752_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_752_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_752_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_752_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_752_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_752_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_752_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_752_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_752_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_752_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_752_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_752_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_752_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_752_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_753(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 229;
  test.test_number = 753;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565759UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_753_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_753_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_753_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_753_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_753_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_753_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_753_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_753_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_753_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_753_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_753_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_753_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_753_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_753_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_754(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 109;
  test.test_number = 754;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565760UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_754_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_754_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_754_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_754_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_754_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_754_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_754_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_754_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_754_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_754_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_754_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_754_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_754_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_754_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_755(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 155;
  test.test_number = 755;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2004565759UL;
  test_acc->result_lamports = 2004565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_755_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_755_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_755_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_755_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_755_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_755_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_755_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_755_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_755_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_755_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_755_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_755_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_755_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_755_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_756(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 200;
  test.test_number = 756;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_756_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_756_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_756_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_756_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_756_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_756_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_756_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_756_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_756_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_756_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_756_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_756_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_756_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_756_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_757(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 68;
  test.test_number = 757;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_757_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_757_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_757_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_757_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_757_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_757_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_757_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_757_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_757_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_757_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_757_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_757_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_757_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_757_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_758(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 143;
  test.test_number = 758;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_758_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_758_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_758_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_758_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_758_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_758_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_758_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_758_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_758_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_758_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_758_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_758_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_758_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_758_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_759(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 105,114,87,116,29,112,90,33,24,55,78,123,113,126,121,106,89,124,108,83,26,127,79,61,128,118,77,120,76,80,30,82,56,27,75,122,103,125,15,62,2,92,117,109,111,110,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 80;
  test.test_number = 759;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_759_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_759_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_759_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_759_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_759_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_759_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_759_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_759_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_759_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_759_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_759_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_759_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_759_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_759_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_760(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 130;
  test.test_number = 760;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_760_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_760_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_760_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_760_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_760_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_760_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_760_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_760_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_760_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_760_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_760_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_760_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_760_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_760_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_761(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 227;
  test.test_number = 761;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565758UL;
  test_acc->result_lamports = 4565758UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_761_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_761_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_761_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_761_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_761_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_761_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_761_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_761_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_761_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_761_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_761_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_761_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_761_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_761_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_762(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 118;
  test.test_number = 762;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_762_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_762_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_762_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_762_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_762_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_762_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_762_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_762_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_762_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_762_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_762_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_762_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_762_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_762_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_763(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 180;
  test.test_number = 763;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565758UL;
  test_acc->result_lamports = 4565758UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_763_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_763_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_763_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_763_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_763_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_763_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_763_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_763_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_763_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_763_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_763_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_763_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_763_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_763_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_764(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 151;
  test.test_number = 764;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_764_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_764_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_764_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_764_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_764_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_764_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_764_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_764_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_764_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_764_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_764_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_764_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_764_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_764_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_765(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 173;
  test.test_number = 765;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_765_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_765_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_765_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_765_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_765_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_765_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_765_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_765_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_765_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_765_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_765_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_765_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_765_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_765_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_766(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 255;
  test.test_number = 766;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_766_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_766_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_766_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_766_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_766_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_766_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_766_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_766_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_766_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_766_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_766_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_766_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_766_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_766_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_767(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 73;
  test.test_number = 767;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_767_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_767_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_767_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_767_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_767_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_767_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_767_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_767_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_767_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_767_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_767_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_767_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_767_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_767_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_768(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 135;
  test.test_number = 768;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_768_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_768_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_768_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_768_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_768_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_768_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_768_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_768_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_768_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_768_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_768_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_768_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_768_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_768_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_769(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 145;
  test.test_number = 769;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565759UL;
  test_acc->result_lamports = 4565759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_769_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_769_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_769_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_769_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_769_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_769_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_769_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_769_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_769_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_769_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_769_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_769_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_769_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_769_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_770(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 205;
  test.test_number = 770;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_770_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_770_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_770_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_770_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_770_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_770_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_770_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_770_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_770_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_770_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_770_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_770_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_770_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_770_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_771(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 85;
  test.test_number = 771;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565760UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_771_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_771_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_771_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_771_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_771_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_771_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_771_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_771_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_771_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_771_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_771_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_771_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_771_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_771_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_772(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 102;
  test.test_number = 772;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_772_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_772_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_772_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_772_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_772_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_772_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_772_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_772_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_772_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_772_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_772_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_772_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_772_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_772_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_773(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,62,27,90,78,55,92,125,117,30,29,121,122,77,87,89,80,124,116,110,98,15,128,109,75,26,123,120,106,126,111,79,83,127,118,103,114,24,33,76,112,82,56,61,2,113,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 192;
  test.test_number = 773;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565761UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_773_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_773_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_773_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_773_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_773_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_773_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_773_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_773_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_773_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_773_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_773_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_773_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_773_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_773_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_774(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 110;
  test.test_number = 774;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4565762UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_774_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_774_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_774_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_774_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_774_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_774_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_774_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_774_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_774_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_774_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_774_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_774_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_774_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_774_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
