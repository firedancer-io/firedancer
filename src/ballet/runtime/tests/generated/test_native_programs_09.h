#include "../fd_tests.h"
int test_225(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,128,118,15,122,108,106,127,98,61,55,87,78,109,89,26,30,123,33,24,92,82,2,126,79,114,105,77,113,90,80,117,116,111,121,62,103,29,125,76,75,124,120,27,110,83,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 254;
  test.test_number = 225;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "G4QCZPTXS9mvh14HjTDFxFAWfDGSeVVMJLKcMo2RqbxR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_225_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_225_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_225_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_225_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GbyegxSFtBspJA7xvbH62orotuzotGCGXf8sMJkNX7Y2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_225_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_225_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_225_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_225_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_225_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_225_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_225_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_225_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_225_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_225_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_225_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_225_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_225_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_225_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_225_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_225_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_225_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_225_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_226(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,128,118,15,122,108,106,127,98,61,55,87,78,109,89,26,30,123,33,24,92,82,2,126,79,114,105,77,113,90,80,117,116,111,121,62,103,29,125,76,75,124,120,27,110,83,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 446;
  test.test_number = 226;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "G4QCZPTXS9mvh14HjTDFxFAWfDGSeVVMJLKcMo2RqbxR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_226_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_226_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_226_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_226_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GbyegxSFtBspJA7xvbH62orotuzotGCGXf8sMJkNX7Y2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_226_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_226_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_226_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_226_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_226_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_226_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_226_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_226_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_226_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_226_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_226_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_226_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_226_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_226_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_226_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_226_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_226_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_226_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_227(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,128,118,15,122,108,106,127,98,61,55,87,78,109,89,26,30,123,33,24,92,82,2,126,79,114,105,77,113,90,80,117,116,111,121,62,103,29,125,76,75,124,120,27,110,83,112 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_deactivate::old_behavior";
  test.test_nonce  = 504;
  test.test_number = 227;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "G4QCZPTXS9mvh14HjTDFxFAWfDGSeVVMJLKcMo2RqbxR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_227_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_227_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_227_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_227_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GbyegxSFtBspJA7xvbH62orotuzotGCGXf8sMJkNX7Y2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_227_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_227_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_227_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_227_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_227_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_227_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_227_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_227_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_227_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_227_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_227_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_227_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_227_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_227_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_227_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_227_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_227_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_227_raw_sz;
  test.expected_result = -26;
  test.custom_err = 2;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_228(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 249;
  test.test_number = 228;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ALtCJi5e3S4mR4MffWUwKSm3QDUBUArtCifXdToQedq9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_228_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_228_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_228_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_228_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HmTTCcPAnjwd6GRG7UYskW4M5cPp2eRfcdNdANQAGUXu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_228_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_228_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_228_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_228_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_228_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_228_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_228_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_228_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_228_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_228_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_228_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_228_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_228_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_228_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_228_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_228_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_228_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_228_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_229(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 27;
  test.test_number = 229;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ALtCJi5e3S4mR4MffWUwKSm3QDUBUArtCifXdToQedq9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_229_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_229_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_229_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_229_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HmTTCcPAnjwd6GRG7UYskW4M5cPp2eRfcdNdANQAGUXu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_229_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_229_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_229_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_229_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_229_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_229_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_229_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_229_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_229_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_229_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_229_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_229_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_229_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_229_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_229_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_229_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_229_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_229_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_230(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 379;
  test.test_number = 230;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ALtCJi5e3S4mR4MffWUwKSm3QDUBUArtCifXdToQedq9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_230_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_230_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_230_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_230_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HmTTCcPAnjwd6GRG7UYskW4M5cPp2eRfcdNdANQAGUXu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_230_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_230_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_230_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_230_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_230_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_230_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_230_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_230_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_230_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_230_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_230_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_230_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_230_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_230_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_230_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_230_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_230_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_230_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_231(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 444;
  test.test_number = 231;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ALtCJi5e3S4mR4MffWUwKSm3QDUBUArtCifXdToQedq9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_231_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_231_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_231_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_231_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HmTTCcPAnjwd6GRG7UYskW4M5cPp2eRfcdNdANQAGUXu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_231_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_231_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_231_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_231_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_231_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_231_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_231_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_231_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_231_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_231_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_231_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_231_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_231_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_231_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_231_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_231_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_231_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_231_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_232(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 305;
  test.test_number = 232;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3atw1cJsxPZC8whad8QcnbiJwp7JJYVBJ9oanN5Tnpni",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_232_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_232_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_232_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_232_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Gm7drA9TWNYLCfFBXxdPYpgStt4JyLeaJhGmWVmRhocc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_232_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_232_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_232_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_232_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_232_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_232_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_232_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_232_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_232_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_232_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_232_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_232_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_232_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_232_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_232_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_232_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_232_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_232_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_233(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 32;
  test.test_number = 233;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3atw1cJsxPZC8whad8QcnbiJwp7JJYVBJ9oanN5Tnpni",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_233_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_233_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_233_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_233_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Gm7drA9TWNYLCfFBXxdPYpgStt4JyLeaJhGmWVmRhocc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_233_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_233_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_233_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_233_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_233_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_233_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_233_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_233_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_233_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_233_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_233_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_233_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_233_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_233_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_233_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_233_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_233_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_233_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_234(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 363;
  test.test_number = 234;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3atw1cJsxPZC8whad8QcnbiJwp7JJYVBJ9oanN5Tnpni",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_234_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_234_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_234_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_234_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Gm7drA9TWNYLCfFBXxdPYpgStt4JyLeaJhGmWVmRhocc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_234_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_234_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_234_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_234_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_234_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_234_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_234_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_234_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_234_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_234_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_234_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_234_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_234_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_234_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_234_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_234_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_234_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_234_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_235(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,92,98,61,24,77,90,118,116,15,114,126,80,30,76,122,56,87,27,108,79,123,26,55,29,112,111,110,113,117,89,121,2,103,82,33,109,75,120,128,127,106,125,83,105,78,124 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 413;
  test.test_number = 235;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3atw1cJsxPZC8whad8QcnbiJwp7JJYVBJ9oanN5Tnpni",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_235_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_235_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_235_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_235_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Gm7drA9TWNYLCfFBXxdPYpgStt4JyLeaJhGmWVmRhocc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_235_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_235_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_235_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_235_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_235_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_235_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_235_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_235_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_235_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_235_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_235_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_235_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_235_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_235_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_235_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_235_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_235_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_235_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_236(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 30;
  test.test_number = 236;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4aJzdE7sqXj9ZQ1ntUzcCaxBVGteqNHxvE7yUZpMRUBA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_236_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_236_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_236_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_236_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Bgjm5nmxomBw9RFoGCCFaSGMuLd5qvyTUWdJTyis4R1D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_236_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_236_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_236_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_236_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_236_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_236_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_236_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_236_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_236_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_236_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_236_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_236_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_236_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_236_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_236_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_236_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_236_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_236_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_237(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 338;
  test.test_number = 237;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4aJzdE7sqXj9ZQ1ntUzcCaxBVGteqNHxvE7yUZpMRUBA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_237_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_237_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_237_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_237_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Bgjm5nmxomBw9RFoGCCFaSGMuLd5qvyTUWdJTyis4R1D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_237_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_237_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_237_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_237_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_237_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_237_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_237_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_237_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_237_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_237_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_237_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_237_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_237_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_237_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_237_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_237_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_237_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_237_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_238(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 414;
  test.test_number = 238;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4aJzdE7sqXj9ZQ1ntUzcCaxBVGteqNHxvE7yUZpMRUBA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_238_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_238_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_238_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_238_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Bgjm5nmxomBw9RFoGCCFaSGMuLd5qvyTUWdJTyis4R1D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_238_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_238_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_238_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_238_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_238_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_238_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_238_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_238_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_238_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_238_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_238_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_238_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_238_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_238_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_238_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_238_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_238_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_238_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_239(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 450;
  test.test_number = 239;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4aJzdE7sqXj9ZQ1ntUzcCaxBVGteqNHxvE7yUZpMRUBA",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_239_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_239_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_239_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_239_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Bgjm5nmxomBw9RFoGCCFaSGMuLd5qvyTUWdJTyis4R1D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_239_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_239_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_239_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_239_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_239_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_239_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_239_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_239_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_239_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_239_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_239_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_239_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_239_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_239_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_239_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_239_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_239_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_239_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_240(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,24,79,116,77,111,56,26,83,92,109,62,98,121,55,117,123,33,87,112,89,75,120,118,114,126,103,76,78,82,61,106,122,110,113,125,128,2,15,30,27,29,127,124,105,80,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 235;
  test.test_number = 240;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nK7wcTVALDujrFQE8piPHYRHoHALwJwGyegbVVYoYU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_240_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_240_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_240_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_240_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "73hPPX7Lz1L87HzvjG1svMMksQUXwhdeScu1kKyGqdWj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_240_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_240_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_240_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_240_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_240_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_240_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_240_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_240_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_240_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_240_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_240_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_240_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_240_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_240_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_240_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_240_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_240_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_240_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_241(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,24,79,116,77,111,56,26,83,92,109,62,98,121,55,117,123,33,87,112,89,75,120,118,114,126,103,76,78,82,61,106,122,110,113,125,128,2,15,30,27,29,127,124,105,80,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 331;
  test.test_number = 241;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nK7wcTVALDujrFQE8piPHYRHoHALwJwGyegbVVYoYU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_241_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_241_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_241_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_241_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "73hPPX7Lz1L87HzvjG1svMMksQUXwhdeScu1kKyGqdWj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_241_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_241_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_241_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_241_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_241_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_241_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_241_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_241_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_241_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_241_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_241_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_241_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_241_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_241_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_241_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_241_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_241_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_241_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_242(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,24,79,116,77,111,56,26,83,92,109,62,98,121,55,117,123,33,87,112,89,75,120,118,114,126,103,76,78,82,61,106,122,110,113,125,128,2,15,30,27,29,127,124,105,80,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 35;
  test.test_number = 242;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nK7wcTVALDujrFQE8piPHYRHoHALwJwGyegbVVYoYU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_242_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_242_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_242_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_242_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "73hPPX7Lz1L87HzvjG1svMMksQUXwhdeScu1kKyGqdWj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_242_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_242_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_242_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_242_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_242_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_242_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_242_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_242_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_242_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_242_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_242_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_242_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_242_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_242_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_242_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_242_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_242_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_242_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_243(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,24,79,116,77,111,56,26,83,92,109,62,98,121,55,117,123,33,87,112,89,75,120,118,114,126,103,76,78,82,61,106,122,110,113,125,128,2,15,30,27,29,127,124,105,80,108 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_delegate_minimum_stake_delegation::old_behavior";
  test.test_nonce  = 380;
  test.test_number = 243;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8nK7wcTVALDujrFQE8piPHYRHoHALwJwGyegbVVYoYU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_243_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_243_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_243_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_243_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "73hPPX7Lz1L87HzvjG1svMMksQUXwhdeScu1kKyGqdWj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_243_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_243_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_243_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_243_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_243_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_243_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_243_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_243_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_243_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_243_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_243_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_243_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_243_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_243_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_243_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_243_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_243_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_243_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_244(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 16;
  test.test_number = 244;
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
  test_acc->data            = fd_flamenco_native_prog_test_244_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_244_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_244_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_244_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_244_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_244_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_244_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_244_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_244_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_244_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_244_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_244_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_244_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_244_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_245(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 12;
  test.test_number = 245;
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
  test_acc->data            = fd_flamenco_native_prog_test_245_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_245_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_245_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_245_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_245_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_245_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_245_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_245_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_245_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_245_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_245_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_245_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_245_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_245_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_246(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 48;
  test.test_number = 246;
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
  test_acc->data            = fd_flamenco_native_prog_test_246_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_246_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_246_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_246_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_246_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_246_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_246_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_246_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_246_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_246_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_246_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_246_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_246_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_246_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_247(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 76;
  test.test_number = 247;
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
  test_acc->data            = fd_flamenco_native_prog_test_247_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_247_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_247_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_247_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_247_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_247_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_247_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_247_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_247_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_247_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_247_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_247_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_247_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_247_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_248(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 93;
  test.test_number = 248;
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
  test_acc->data            = fd_flamenco_native_prog_test_248_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_248_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_248_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_248_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111114DhpssPJgSi1YU7hCMfYt1BJ334YgsffXm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282878UL;
  test_acc->result_lamports = 2282878UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_248_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_248_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_248_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_248_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_248_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_248_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_248_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_248_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_248_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_248_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_249(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 24,103,55,122,98,108,75,126,82,2,116,80,15,29,121,124,27,110,76,118,109,92,90,127,26,33,105,123,106,117,78,113,62,83,111,30,125,79,56,128,87,77,120,89,112,61,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_initialized_split_destination_minimum_balance::new_behavior";
  test.test_nonce  = 42;
  test.test_number = 249;
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
  test_acc->data            = fd_flamenco_native_prog_test_249_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_249_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_249_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_249_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111152P2r5yt6odmBLPsFCLBrFisJ3aS7LqLAT",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_249_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_249_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_249_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_249_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_249_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_249_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_249_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_249_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_249_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_249_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
