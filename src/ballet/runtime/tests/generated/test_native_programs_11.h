#include "../fd_tests.h"
int test_275(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 143;
  test.test_number = 275;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111114d3RrygbPdAtMuFnDmzsN8T5fYKVQ7FVr7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_275_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_275_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_275_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_275_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_275_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_275_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_275_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_275_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_275_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_275_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_275_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_275_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_275_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_275_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_276(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::new_behavior";
  test.test_nonce  = 15;
  test.test_number = 276;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2X77Z4mDvbKopQK3qZ4DdYY7PWr4TMwNzy4z2GbQpcTn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_276_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_276_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_276_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_276_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_276_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_276_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_276_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_276_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_276_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_276_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_277(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::new_behavior";
  test.test_nonce  = 8;
  test.test_number = 277;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2X77Z4mDvbKopQK3qZ4DdYY7PWr4TMwNzy4z2GbQpcTn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_277_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_277_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_277_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_277_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_277_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_277_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_277_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_277_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_277_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_277_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_278(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,118,103,121,116,108,77,83,80,98,75,15,61,111,112,123,125,78,87,79,30,92,33,117,2,89,128,114,122,90,127,110,124,56,120,27,126,26,105,113,29,76,55,109,82,62,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::new_behavior";
  test.test_nonce  = 0;
  test.test_number = 278;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EwiuvqbR8WcBJvR5k1R5sJd87JGBQGyvGtZ1Dsi5pHHe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_278_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_278_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_278_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_278_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_278_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_278_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_278_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_278_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_278_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_278_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_279(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,118,103,121,116,108,77,83,80,98,75,15,61,111,112,123,125,78,87,79,30,92,33,117,2,89,128,114,122,90,127,110,124,56,120,27,126,26,105,113,29,76,55,109,82,62,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::new_behavior";
  test.test_nonce  = 54;
  test.test_number = 279;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EwiuvqbR8WcBJvR5k1R5sJd87JGBQGyvGtZ1Dsi5pHHe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_279_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_279_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_279_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_279_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_279_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_279_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_279_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_279_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_279_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_279_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_280(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,112,80,127,126,24,29,121,87,26,83,78,2,75,56,128,103,124,110,30,98,123,108,106,117,90,125,33,113,92,15,120,89,77,76,118,116,122,62,55,27,61,105,82,114,111,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::old_behavior";
  test.test_nonce  = 1;
  test.test_number = 280;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "C28ex2CRW1fpzcKhRXWAx9y5BBx6SJzon3kh4xa8TQA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_280_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_280_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_280_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_280_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_280_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_280_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_280_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_280_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_280_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_280_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_281(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 109,112,80,127,126,24,29,121,87,26,83,78,2,75,56,128,103,124,110,30,98,123,108,106,117,90,125,33,113,92,15,120,89,77,76,118,116,122,62,55,27,61,105,82,114,111,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::old_behavior";
  test.test_nonce  = 51;
  test.test_number = 281;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "C28ex2CRW1fpzcKhRXWAx9y5BBx6SJzon3kh4xa8TQA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_281_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_281_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_281_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_281_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_281_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_281_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_281_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_281_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_281_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_281_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_282(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::old_behavior";
  test.test_nonce  = 16;
  test.test_number = 282;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9EiKetW4pvoR5KER1g3Br8Ga5kTQ7VnCQPnupXTiHHoE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_282_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_282_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_282_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_282_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_282_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_282_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_282_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_282_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_282_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_282_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_283(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialize_minimum_balance::old_behavior";
  test.test_nonce  = 2;
  test.test_number = 283;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9EiKetW4pvoR5KER1g3Br8Ga5kTQ7VnCQPnupXTiHHoE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_283_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_283_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_283_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_283_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_283_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_283_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_283_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_283_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_283_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_283_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_284(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 209;
  test.test_number = 284;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_284_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_284_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_284_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_284_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_284_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_284_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_284_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_284_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_284_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_284_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_284_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_284_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_284_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_284_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_284_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_284_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_284_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_284_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_284_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_284_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_284_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_284_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_285(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 22;
  test.test_number = 285;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_285_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_285_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_285_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_285_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_285_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_285_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_285_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_285_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_285_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_285_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_285_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_285_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_285_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_285_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_285_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_285_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_285_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_285_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_285_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_285_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_285_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_285_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_286(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 335;
  test.test_number = 286;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_286_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_286_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_286_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_286_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_286_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_286_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_286_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_286_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_286_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_286_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_286_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_286_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_286_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_286_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_286_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_286_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_286_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_286_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_286_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_286_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_286_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_286_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_287(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 391;
  test.test_number = 287;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_287_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_287_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_287_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_287_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_287_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_287_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_287_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_287_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_287_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_287_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_287_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_287_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_287_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_287_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_287_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_287_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_287_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_287_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_287_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_287_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_287_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_287_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_288(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 452;
  test.test_number = 288;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_288_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_288_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_288_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_288_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_288_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_288_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_288_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_288_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_288_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_288_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_288_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_288_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_288_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_288_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_288_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_288_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_288_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_288_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_288_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_288_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_288_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_288_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_289(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 485;
  test.test_number = 289;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_289_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_289_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_289_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_289_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_289_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_289_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_289_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_289_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_289_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_289_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_289_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_289_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_289_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_289_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_289_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_289_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_289_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_289_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_289_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_289_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_289_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_289_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_290(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 509;
  test.test_number = 290;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_290_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_290_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_290_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_290_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_290_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_290_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_290_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_290_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_290_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_290_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_290_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_290_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_290_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_290_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_290_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_290_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_290_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_290_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_290_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_290_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_290_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_290_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_291(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 528;
  test.test_number = 291;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_291_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_291_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_291_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_291_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_291_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_291_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_291_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_291_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_291_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_291_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_291_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_291_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_291_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_291_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_291_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_291_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_291_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_291_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_291_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_291_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_291_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_291_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_292(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 548;
  test.test_number = 292;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_292_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_292_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_292_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_292_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_292_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_292_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_292_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_292_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_292_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_292_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_292_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_292_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_292_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_292_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_292_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_292_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_292_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_292_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_292_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_292_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_292_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_292_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_293(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 564;
  test.test_number = 293;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_293_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_293_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_293_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_293_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_293_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_293_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_293_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_293_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_293_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_293_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_293_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_293_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_293_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_293_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_293_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_293_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_293_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_293_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_293_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_293_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_293_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_293_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_294(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 583;
  test.test_number = 294;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_294_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_294_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_294_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_294_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_294_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_294_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_294_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_294_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_294_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_294_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_294_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_294_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_294_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_294_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_294_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_294_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_294_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_294_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_294_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_294_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_294_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_294_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_295(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 593;
  test.test_number = 295;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_295_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_295_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_295_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_295_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 8489414244UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_295_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_295_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_295_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_295_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_295_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_295_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_295_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_295_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_295_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_295_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_295_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_295_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_295_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_295_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_295_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_295_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_295_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_295_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_296(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 601;
  test.test_number = 296;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_296_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_296_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_296_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_296_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_296_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_296_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_296_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_296_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_296_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_296_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_296_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_296_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_296_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_296_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_296_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_296_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_296_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_296_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_296_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_296_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_296_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_296_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_297(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 608;
  test.test_number = 297;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_297_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_297_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_297_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_297_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_297_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_297_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_297_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_297_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_297_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_297_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_297_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_297_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_297_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_297_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_297_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_297_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_297_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_297_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_297_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_297_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_297_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_297_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_298(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 615;
  test.test_number = 298;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_298_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_298_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_298_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_298_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_298_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_298_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_298_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_298_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_298_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_298_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_298_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_298_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_298_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_298_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_298_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_298_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_298_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_298_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_298_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_298_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_298_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_298_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_299(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,108,78,79,128,61,117,124,33,116,114,111,121,62,27,98,126,82,112,90,75,24,92,2,55,120,106,76,122,109,80,105,127,56,87,26,123,118,125,15,77,103,29,89,30,110,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_active_stake::new_behavior";
  test.test_nonce  = 621;
  test.test_number = 299;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nDyGaaLD2E5NbpQKqtqyt8QYKwc3CdxeKPkddmCpDRp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_299_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_299_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_299_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_299_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3nWKsRHcGZMkxCqxwzoSkJL75s5d8c6KpzRfmtkuvQuH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_299_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_299_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_299_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_299_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HpKz3VfNTNBTdJS8PAqTGoEPk9RAHqBNmVjYhWxa3fUy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_299_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_299_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_299_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_299_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_299_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_299_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_299_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_299_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_299_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_299_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_299_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_299_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_299_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_299_raw_sz;
  test.expected_result = -26;
  test.custom_err = 5;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
