#include "../fd_tests.h"
int test_250(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 56;
  test.test_number = 250;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111114d3RrygbPdAtMuFnDmzsN8T5fYKVQ7FVr7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_250_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_250_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_250_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_250_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_250_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_250_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_250_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_250_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_250_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_250_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_250_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_250_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_250_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_250_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_251(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 78;
  test.test_number = 251;
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
  test_acc->data            = fd_flamenco_native_prog_test_251_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_251_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_251_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_251_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282878UL;
  test_acc->result_lamports = 2282878UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_251_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_251_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_251_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_251_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_251_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_251_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_251_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_251_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_251_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_251_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_252(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 147;
  test.test_number = 252;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_252_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_252_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_252_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_252_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_252_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_252_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_252_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_252_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_252_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_252_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_252_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_252_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_252_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_252_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_253(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 105;
  test.test_number = 253;
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
  test_acc->data            = fd_flamenco_native_prog_test_253_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_253_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_253_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_253_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_253_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_253_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_253_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_253_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_253_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_253_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_253_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_253_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_253_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_253_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_254(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 119;
  test.test_number = 254;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_254_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_254_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_254_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_254_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_254_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_254_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_254_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_254_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_254_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_254_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_254_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_254_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_254_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_254_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_255(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 186;
  test.test_number = 255;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_255_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_255_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_255_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_255_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_255_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_255_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_255_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_255_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_255_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_255_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_255_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_255_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_255_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_255_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_256(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 153;
  test.test_number = 256;
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
  test_acc->data            = fd_flamenco_native_prog_test_256_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_256_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_256_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_256_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_256_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_256_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_256_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_256_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_256_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_256_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_256_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_256_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_256_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_256_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_257(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 91;
  test.test_number = 257;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111114d3RrygbPdAtMuFnDmzsN8T5fYKVQ7FVr7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268736UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_257_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_257_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_257_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_257_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_257_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_257_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_257_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_257_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_257_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_257_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_257_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_257_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_257_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_257_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_258(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 171;
  test.test_number = 258;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_258_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_258_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_258_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_258_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_258_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_258_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_258_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_258_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_258_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_258_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_258_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_258_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_258_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_258_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_259(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 124;
  test.test_number = 259;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111114d3RrygbPdAtMuFnDmzsN8T5fYKVQ7FVr7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268735UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_259_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_259_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_259_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_259_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_259_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_259_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_259_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_259_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_259_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_259_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_259_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_259_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_259_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_259_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_260(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 7;
  test.test_number = 260;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_260_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_260_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_260_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_260_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_260_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_260_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_260_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_260_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_260_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_260_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_260_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_260_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_260_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_260_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_261(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 8;
  test.test_number = 261;
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
  test_acc->data            = fd_flamenco_native_prog_test_261_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_261_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_261_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_261_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_261_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_261_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_261_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_261_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_261_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_261_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_261_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_261_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_261_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_261_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_262(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 19;
  test.test_number = 262;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_262_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_262_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_262_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_262_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_262_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_262_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_262_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_262_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_262_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_262_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_262_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_262_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_262_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_262_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_263(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 41;
  test.test_number = 263;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_263_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_263_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_263_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_263_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_263_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_263_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_263_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_263_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_263_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_263_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_263_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_263_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_263_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_263_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_264(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 50;
  test.test_number = 264;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_264_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_264_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_264_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_264_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282878UL;
  test_acc->result_lamports = 2282878UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_264_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_264_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_264_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_264_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_264_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_264_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_264_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_264_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_264_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_264_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_265(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 40;
  test.test_number = 265;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111114d3RrygbPdAtMuFnDmzsN8T5fYKVQ7FVr7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551614UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_265_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_265_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_265_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_265_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_265_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_265_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_265_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_265_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_265_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_265_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_265_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_265_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_265_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_265_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_266(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 43;
  test.test_number = 266;
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
  test_acc->data            = fd_flamenco_native_prog_test_266_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_266_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_266_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_266_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_266_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_266_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_266_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_266_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_266_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_266_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_266_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_266_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_266_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_266_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_267(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 79;
  test.test_number = 267;
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
  test_acc->data            = fd_flamenco_native_prog_test_267_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_267_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_267_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_267_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282878UL;
  test_acc->result_lamports = 2282878UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_267_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_267_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_267_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_267_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_267_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_267_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_267_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_267_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_267_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_267_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_268(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 79;
  test.test_number = 268;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_268_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_268_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_268_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_268_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_268_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_268_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_268_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_268_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_268_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_268_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_268_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_268_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_268_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_268_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_269(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 117;
  test.test_number = 269;
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
  test_acc->data            = fd_flamenco_native_prog_test_269_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_269_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_269_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_269_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_269_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_269_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_269_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_269_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_269_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_269_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_269_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_269_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_269_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_269_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_270(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 111;
  test.test_number = 270;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073709551615UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_270_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_270_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_270_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_270_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_270_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_270_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_270_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_270_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_270_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_270_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_270_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_270_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_270_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_270_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_271(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 62;
  test.test_number = 271;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268736UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_271_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_271_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_271_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_271_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_271_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_271_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_271_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_271_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_271_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_271_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_271_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_271_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_271_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_271_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_272(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 164;
  test.test_number = 272;
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
  test_acc->data            = fd_flamenco_native_prog_test_272_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_272_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_272_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_272_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_272_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_272_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_272_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_272_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_272_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_272_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_272_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_272_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_272_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_272_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_273(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,27,29,120,109,116,79,83,55,113,112,118,26,128,82,111,92,77,62,75,2,122,103,33,90,98,76,15,89,106,108,127,80,87,126,30,121,117,114,123,125,105,124,61,78,24,110 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 92;
  test.test_number = 273;
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
  test_acc->data            = fd_flamenco_native_prog_test_273_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_273_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_273_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_273_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_273_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_273_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_273_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_273_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_273_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_273_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_273_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_273_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_273_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_273_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_274(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::old_behavior";
  test.test_nonce  = 94;
  test.test_number = 274;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111113pNDtm61yGF8j2ycAwLEPsuWQXobye5qDR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 18446744073709551615UL;
  test_acc->result_lamports = 18446744073707268735UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_274_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_274_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_274_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_274_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_274_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_274_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_274_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_274_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_274_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_274_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_274_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_274_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_274_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_274_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
