#include "../fd_tests.h"
int test_925(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 150;
  test.test_number = 925;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_925_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_925_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_925_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_925_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_925_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_925_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_925_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_925_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111PwGP8BzRUHQwchwwPuzAe9WqskgmXMFV2f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_925_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_925_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_925_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_925_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_925_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_925_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_925_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_925_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_925_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_925_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_926(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 176;
  test.test_number = 926;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111SMJ12qn9jNCCXJnTYRz5Yu9ZenERnkkUvj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_926_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_926_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_926_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_926_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111RwxQ3jUs2BjKhseNX1em4msn2GyV5XAecP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_926_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_926_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_926_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_926_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_926_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_926_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_926_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_926_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_926_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_926_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_926_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_926_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_926_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_926_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_927(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 430;
  test.test_number = 927;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111uJwR17kTJTEuKM8GBYJS3JPGpaVdRSqJ7q",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_927_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_927_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_927_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_927_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_927_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_927_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_927_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_927_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_927_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_927_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_927_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_927_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111tubp21TAbGn2VuzBA7y7ZB7VC5EgiDFToV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_927_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_927_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_927_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_927_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_927_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_927_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_928(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 515;
  test.test_number = 928;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111229gfjxpMNX7oDiVjbfxrHS1eX9sfWRkTVh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_928_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_928_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_928_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_928_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_928_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_928_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_928_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_928_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111122Z2Gj57e5hag39dpd6JAmZHS9f8cDfLHp3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_928_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_928_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_928_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_928_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_928_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_928_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_928_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_928_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_928_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_928_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_928_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_928_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_928_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_928_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_929(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 471;
  test.test_number = 929;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111zYLFoXdCXoGHwywPVzdaLvvW18qtfVR8EK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_929_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_929_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_929_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_929_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_929_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_929_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_929_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_929_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_929_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_929_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_929_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_929_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111z8zepRKupcoR8YoJUaJFroeiNdawxFqHuy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_929_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_929_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_929_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_929_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_929_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_929_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_929_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_929_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_929_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_929_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_930(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 549;
  test.test_number = 930;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_930_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_930_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_930_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_930_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111128BkiWbHg2E4wVDb2xxxdZK6SxijpAwVxEs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_930_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_930_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_930_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_930_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_930_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_930_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_930_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_930_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_930_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_930_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_931(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 502;
  test.test_number = 931;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_931_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_931_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_931_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_931_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_931_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_931_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_931_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_931_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111127P5WYNh6bs9BrMJrv8Hzb4YshiDvkULHcB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_931_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_931_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_931_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_931_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_931_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_931_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_932(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 558;
  test.test_number = 932;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_932_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_932_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_932_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_932_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112AbnLRF5QHJrCPpRZ7UxYU4jAjkHUSLzx8w",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_932_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_932_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_932_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_932_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_932_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_932_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_932_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_932_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_932_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_932_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_933(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 507;
  test.test_number = 933;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_933_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_933_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_933_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_933_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_933_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_933_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_933_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_933_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111128b6KVhaxjQXpJej7zPHx3SNEbDzktB5nZD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_933_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_933_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_933_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_933_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_933_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_933_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_934(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 252;
  test.test_number = 934;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_934_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_934_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_934_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_934_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_934_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_934_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_934_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_934_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111bCjGhELVMLPUWqrN5fK6Df8sVsuBRuaotK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_934_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_934_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_934_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_934_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_934_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_934_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_934_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_934_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111bc4sgLdn4WrMLGzT75eQhnQf8PA899AeCf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_934_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_934_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_934_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_934_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_934_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_934_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_935(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 394;
  test.test_number = 935;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_935_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_935_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_935_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_935_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111mGBMJwnh6qyNxgLXh9e4LnwYEVLmCmAdnw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_935_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_935_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_935_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_935_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_935_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_935_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_935_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_935_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_935_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_935_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_935_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_935_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111mfWxJ45yp2SFn7UciZyNpvDKrzbhuzkU7H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_935_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_935_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_935_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_935_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_935_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_935_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_936(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 239;
  test.test_number = 936;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_936_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_936_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_936_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_936_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_936_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_936_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_936_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_936_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_936_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_936_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_936_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_936_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_936_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_936_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_936_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_936_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Xz2SpMxBftgTyNjftJeYLexaTqqdk2v9MZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_936_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_936_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_936_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_936_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_936_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_936_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_937(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 378;
  test.test_number = 937;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_937_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_937_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_937_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_937_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111nUCAGGgZEPN1QyknmQe1oAku817bLTv8jy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_937_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_937_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_937_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_937_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111n4rZHAPGXCu8bYchjzJhK3V7VVredELJRd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_937_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_937_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_937_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_937_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_937_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_937_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_937_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_937_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_937_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_937_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_937_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_937_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_937_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_937_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_938(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 569;
  test.test_number = 938;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112CcUMLnZqqDAaUz7zEad8th66tGaBzWv7if",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_938_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_938_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_938_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_938_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx31",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_938_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_938_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_938_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_938_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_938_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_938_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_938_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_938_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_938_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_938_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_938_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_938_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_938_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_938_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_939(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 513;
  test.test_number = 939;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111129o78T2UprwvSkx9P4eHuVpBbUjmb1sqHWF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_939_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_939_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_939_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_939_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_939_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_939_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_939_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_939_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_939_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_939_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_939_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_939_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112ACSjS8n7a8PKaPHU64dDywTP7F2Xj7R7pb",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_939_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_939_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_939_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_939_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_939_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_939_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_940(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 579;
  test.test_number = 940;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112EdANGL4HP7Uxa9pRMgHjKKT32nruYgqHJP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_940_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_940_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_940_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_940_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_940_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_940_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_940_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_940_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_940_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_940_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_940_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_940_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112F2VyFSMa6HwqPaxWP6d3oSipfJ7rFvR7cj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_940_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_940_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_940_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_940_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112FRqaEYeroUQiD26bQWxNHZzcHoNny9zww5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_940_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_940_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_940_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_940_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_940_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_940_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_940_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_940_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_940_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_940_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_941(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 78,106,113,116,114,92,128,2,75,56,83,117,33,61,118,27,109,79,122,15,29,87,110,124,103,98,126,90,123,105,89,76,55,125,127,62,30,111,80,26,108,121,82,24,77,112,120 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::new_behavior";
  test.test_nonce  = 519;
  test.test_number = 941;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112Boo9NZyGQrEpr7qpBjxVvSYXdG4Ja3kT5y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_941_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_941_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_941_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_941_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112BQTYPTfyhfmx2ghjAKdBSKGjzkoMrpAcmd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_941_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_941_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_941_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_941_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112CD8kMgGZ82hhfYyuDAHpQZpKFmKFHHLHQK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_941_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_941_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_941_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_941_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_941_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_941_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_941_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_941_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_941_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_941_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_941_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_941_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_941_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_941_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_941_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_941_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_941_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_941_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_942(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 149;
  test.test_number = 942;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_942_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_942_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_942_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_942_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_942_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_942_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_942_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_942_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_942_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_942_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_942_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_942_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_942_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_942_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_943(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 128;
  test.test_number = 943;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_943_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_943_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_943_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_943_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_943_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_943_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_943_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_943_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_943_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_943_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_943_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_943_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_943_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_943_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_944(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 159;
  test.test_number = 944;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_944_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_944_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_944_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_944_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_944_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_944_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_944_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_944_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111PwGP8BzRUHQwchwwPuzAe9WqskgmXMFV2f",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_944_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_944_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_944_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_944_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_944_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_944_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_945(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 177;
  test.test_number = 945;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_945_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_945_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_945_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_945_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_945_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_945_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_945_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_945_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111R9HC5WtHbpoa51NCUAz86XLCmGTbf3zyyh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_945_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_945_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_945_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_945_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_945_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_945_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_946(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 415;
  test.test_number = 946;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_946_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_946_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_946_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_946_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111tWGD2u9st6K9gUr68hdo53qhZZyjzyfdV9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_946_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_946_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_946_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_946_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_946_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_946_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_946_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_946_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111t6vc3nrbAurGs3i17HJUavZuw4ioHk5oAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_946_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_946_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_946_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_946_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_946_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_946_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_946_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_946_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_946_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_946_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_946_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_946_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_946_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_946_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_947(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,126,29,2,76,113,116,123,90,120,127,106,121,15,27,110,111,61,112,117,124,89,92,77,128,98,122,78,118,87,80,82,125,108,105,55,114,56,83,30,26,33,103,24,109,62,79 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 437;
  test.test_number = 947;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_947_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_947_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_947_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_947_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_947_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_947_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_947_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_947_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111rVaC7MfSLBzmbK9f1byCeRUmR3h2SokTuR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_947_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_947_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_947_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_947_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111rtuo6Txj3NTeQkHk32JX8YkZ3YwyA3LJDm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_947_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_947_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_947_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_947_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_947_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_947_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_947_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_947_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_947_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_947_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_947_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_947_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_947_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_947_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_948(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 195;
  test.test_number = 948;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111XBMEr9McFXkiLWTVqTyuNQR1CqKkKZkUis",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_948_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_948_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_948_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_948_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_948_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_948_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_948_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_948_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_948_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_948_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_948_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_948_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Wn1ds34KYMHqX5KQp3eatH9DaL4ocLAeQX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_948_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_948_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_948_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_948_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_948_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_948_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_949(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_spoofed_stake_accounts::old_behavior";
  test.test_nonce  = 218;
  test.test_number = 949;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111c1QUfSw4mhKE9i8Y8VyjBugSktR4rNkUX1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_949_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_949_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_949_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_949_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111cQk5eZEMUsn6y9Gd9vK3g2xEPPg1ZcLJqM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_949_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_949_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_949_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_949_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SpoofedStake1111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Spoofed111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_949_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_949_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_949_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_949_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_949_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_949_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_949_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_949_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_949_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_949_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
