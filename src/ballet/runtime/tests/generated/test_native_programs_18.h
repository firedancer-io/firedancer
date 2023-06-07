#include "../fd_tests.h"
int test_450(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 356;
  test.test_number = 450;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_450_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_450_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_450_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_450_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_450_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_450_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_450_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_450_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_450_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_450_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_450_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_450_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_450_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_450_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_450_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_450_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_450_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_450_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_450_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_450_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_450_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_450_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_451(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 424;
  test.test_number = 451;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_451_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_451_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_451_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_451_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_451_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_451_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_451_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_451_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_451_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_451_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_451_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_451_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_451_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_451_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_451_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_451_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_451_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_451_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_451_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_451_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_451_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_451_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_452(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 479;
  test.test_number = 452;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_452_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_452_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_452_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_452_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_452_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_452_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_452_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_452_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_452_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_452_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_452_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_452_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_452_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_452_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_452_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_452_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_452_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_452_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_452_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_452_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_452_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_452_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_453(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 528;
  test.test_number = 453;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_453_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_453_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_453_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_453_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_453_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_453_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_453_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_453_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_453_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_453_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_453_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_453_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_453_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_453_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_453_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_453_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_453_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_453_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_453_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_453_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_453_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_453_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_454(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 557;
  test.test_number = 454;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_454_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_454_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_454_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_454_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_454_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_454_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_454_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_454_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_454_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_454_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_454_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_454_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_454_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_454_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_454_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_454_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_454_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_454_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_454_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_454_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_454_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_454_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_455(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,122,77,82,108,110,90,83,56,87,114,78,111,128,29,79,61,80,127,106,30,33,117,125,24,126,116,92,76,15,55,124,27,123,75,120,62,109,105,2,103,26,89,98,121,112,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::new_behavior";
  test.test_nonce  = 571;
  test.test_number = 455;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "7KbokcEM7KVi3coyWKKkZ8Ndv2uj4YSkh6nQKw5hnjYP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_455_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_455_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_455_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_455_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "91Nj97K27kSpKn2azjnb6DUNr8ndkmSPBz947JCiieho",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_455_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_455_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_455_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_455_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtrQkPV8u9Zo1yMBG4NDkAjzQ4RKm1acDazeVu88u2Bn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_455_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_455_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_455_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_455_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_455_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_455_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_455_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_455_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_455_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_455_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_455_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_455_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_455_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_455_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_456(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 19;
  test.test_number = 456;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_456_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_456_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_456_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_456_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_456_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_456_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_456_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_456_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_456_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_456_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_456_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_456_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_456_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_456_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_456_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_456_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_456_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_456_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_456_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_456_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_456_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_456_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_457(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 216;
  test.test_number = 457;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_457_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_457_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_457_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_457_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_457_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_457_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_457_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_457_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_457_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_457_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_457_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_457_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_457_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_457_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_457_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_457_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_457_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_457_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_457_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_457_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_457_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_457_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_458(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 326;
  test.test_number = 458;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_458_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_458_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_458_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_458_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_458_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_458_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_458_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_458_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_458_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_458_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_458_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_458_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_458_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_458_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_458_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_458_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_458_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_458_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_458_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_458_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_458_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_458_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_459(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 364;
  test.test_number = 459;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_459_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_459_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_459_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_459_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_459_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_459_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_459_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_459_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_459_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_459_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_459_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_459_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_459_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_459_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_459_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_459_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_459_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_459_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_459_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_459_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_459_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_459_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_460(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 400;
  test.test_number = 460;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_460_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_460_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_460_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_460_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_460_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_460_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_460_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_460_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_460_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_460_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_460_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_460_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_460_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_460_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_460_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_460_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_460_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_460_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_460_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_460_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_460_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_460_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_461(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 431;
  test.test_number = 461;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_461_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_461_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_461_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_461_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_461_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_461_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_461_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_461_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_461_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_461_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_461_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_461_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_461_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_461_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_461_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_461_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_461_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_461_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_461_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_461_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_461_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_461_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_462(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 465;
  test.test_number = 462;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_462_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_462_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_462_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_462_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_462_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_462_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_462_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_462_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_462_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_462_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_462_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_462_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_462_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_462_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_462_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_462_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_462_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_462_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_462_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_462_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_462_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_462_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_463(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,29,116,76,33,114,62,80,82,15,111,108,128,26,118,113,109,125,121,117,30,92,123,127,112,24,103,105,61,75,2,120,56,89,126,55,98,122,83,78,110,124,77,87,79,106,90 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 489;
  test.test_number = 463;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CjPuRbCrHsqmGaokQhgGttmsPYtpNymc6GS8mDTCmuUP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_463_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_463_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_463_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_463_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "G5Ama7fDJnY5KsesoTYeynEyXbvvtWojqr2fEpFJWHxn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_463_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_463_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_463_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_463_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2WCDaJhdF6gCcv28tELhny5YJWGQEZ8Yo4ABcDDt5fjE",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_463_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_463_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_463_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_463_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_463_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_463_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_463_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_463_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_463_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_463_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_463_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_463_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_463_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_463_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_464(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 253;
  test.test_number = 464;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_464_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_464_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_464_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_464_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_464_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_464_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_464_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_464_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_464_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_464_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_464_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_464_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_464_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_464_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_464_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_464_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_464_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_464_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_464_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_464_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_464_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_464_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_465(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 34;
  test.test_number = 465;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_465_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_465_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_465_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_465_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_465_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_465_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_465_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_465_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_465_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_465_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_465_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_465_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_465_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_465_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_465_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_465_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_465_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_465_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_465_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_465_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_465_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_465_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_466(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 353;
  test.test_number = 466;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_466_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_466_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_466_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_466_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_466_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_466_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_466_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_466_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_466_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_466_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_466_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_466_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_466_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_466_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_466_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_466_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_466_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_466_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_466_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_466_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_466_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_466_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_467(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 419;
  test.test_number = 467;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_467_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_467_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_467_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_467_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_467_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_467_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_467_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_467_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_467_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_467_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_467_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_467_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_467_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_467_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_467_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_467_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_467_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_467_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_467_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_467_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_467_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_467_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_468(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 478;
  test.test_number = 468;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_468_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_468_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_468_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_468_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_468_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_468_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_468_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_468_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_468_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_468_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_468_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_468_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_468_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_468_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_468_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_468_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_468_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_468_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_468_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_468_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_468_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_468_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_469(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 527;
  test.test_number = 469;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_469_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_469_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_469_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_469_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_469_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_469_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_469_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_469_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_469_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_469_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_469_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_469_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_469_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_469_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_469_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_469_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_469_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_469_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_469_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_469_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_469_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_469_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_470(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 555;
  test.test_number = 470;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_470_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_470_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_470_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_470_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_470_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_470_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_470_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_470_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_470_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_470_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_470_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_470_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_470_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_470_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_470_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_470_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_470_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_470_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_470_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_470_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_470_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_470_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_471(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge::old_behavior";
  test.test_nonce  = 578;
  test.test_number = 471;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "rnyC1B77sTrgSt81w3xRCDX3DDUHtzNWHbMpFoDjqeW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 84UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_471_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_471_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_471_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_471_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "zeim6s1NhkuQTSYxPiS7KRjJDPGjuPLQvNEBS6dAoEz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_471_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_471_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_471_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_471_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "6dZsJXhLLPEFMniGDDDD2eTNpCUYDQi16mFyAijgkgwv",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_471_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_471_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_471_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_471_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_471_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_471_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_471_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_471_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_471_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_471_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_471_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_471_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_471_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_471_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_472(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 125,117,103,30,110,61,116,126,114,55,124,24,128,87,123,2,76,80,33,105,118,15,56,79,122,77,29,62,89,111,112,78,27,109,113,82,108,127,98,26,83,92,90,75,120,121,106 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_self_fails::new_behavior";
  test.test_nonce  = 24;
  test.test_number = 472;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3238ebC3ToFV2JycghnGg8fVqAjufrChuNMdDmVWXCwZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_472_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_472_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_472_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_472_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Gj2wprzzLAhUyJzZR4SoGXHwXmRLLEJ37EnNrVcLibSS",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_472_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_472_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_472_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_472_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_472_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_472_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_472_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_472_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_472_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_472_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_472_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_472_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_472_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_472_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_473(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 125,117,103,30,110,61,116,126,114,55,124,24,128,87,123,2,76,80,33,105,118,15,56,79,122,77,29,62,89,111,112,78,27,109,113,82,108,127,98,26,83,92,90,75,120,121,106 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_self_fails::new_behavior";
  test.test_nonce  = 25;
  test.test_number = 473;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6c2FrSkFiTq9FG4empfmMaMEgMguqE4e36dWvJsUahcf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_473_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_473_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_473_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_473_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9Ko9RHGELV8ApvCNViGAuv93B1CS451X5iHQhK3HLF2R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_473_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_473_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_473_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_473_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_473_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_473_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_473_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_473_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_473_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_473_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_473_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_473_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_473_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_473_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_474(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_merge_self_fails::old_behavior";
  test.test_nonce  = 39;
  test.test_number = 474;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "eE5jFhUnW1Gim577Bc3ASeXeWgUFMxDZBdgqcoaRDmN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 4244707122UL;
  test_acc->result_lamports = 4244707122UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_474_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_474_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_474_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_474_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FCTVnAdqiApJD3qtXVK22aTfabeKCb7DwxHhHapSXf2m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_474_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_474_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_474_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_474_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_474_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_474_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_474_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_474_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_474_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_474_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_474_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_474_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_474_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_474_raw_sz;
  test.expected_result = -2;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
