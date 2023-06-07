#include "../fd_tests.h"
int test_1325(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 591;
  test.test_number = 1325;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 10UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1325_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1325_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1325_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1325_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1325_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1325_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1326(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 603;
  test.test_number = 1326;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1326_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1326_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1326_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1326_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1326_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1326_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1327(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 630;
  test.test_number = 1327;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1327_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1327_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1327_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1327_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1327_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1327_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1328(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 560;
  test.test_number = 1328;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1328_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1328_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1328_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1328_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1328_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1328_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1329(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 604;
  test.test_number = 1329;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1329_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1329_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1329_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1329_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1329_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1329_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1330(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 594;
  test.test_number = 1330;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1330_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1330_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1330_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1330_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1330_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1330_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1331(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 624;
  test.test_number = 1331;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1331_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1331_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1331_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1331_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1331_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1331_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1332(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 611;
  test.test_number = 1332;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1332_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1332_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1332_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1332_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1332_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1332_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1333(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 636;
  test.test_number = 1333;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1333_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1333_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1333_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1333_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1333_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1333_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1334(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 581;
  test.test_number = 1334;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "4omDQx3gmg2bZqkLjTZoCUadshXV7gMLPEhg5bL5urnq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "C1yhE9JiKDWKyWpGwwLR96Q7ZVfs3fTqcKnWEBBeLR4P",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HVtYUPmJaFWi7Sucsc1Fq7etkoRuqcZjbXBcsvvmuugm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "EQy3NVjkmA8FCjMaB7pFfNzcVGKTRxg8whZwxCCJAAoo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AL7b2h1vjn2okVcxtDovAS2ang4Qscoscmz4pnnzqsM2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1334_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1334_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1334_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1334_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1334_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1334_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1335(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,106,75,55,114,118,113,15,26,128,117,125,83,90,122,78,77,112,79,61,30,109,56,126,111,103,92,62,89,121,2,127,87,29,98,24,123,110,33,116,124,76,120,82,27,105,80 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::new_behavior";
  test.test_nonce  = 615;
  test.test_number = 1335;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DgJh6HV56PK4xx92vU3HpYjmMo2wW28jysJcfXTMhMgw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000010UL;
  test_acc->result_lamports = 1000000010UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CdMT8H8hCLNoQY1sf9iH1KMKGy2WEosyH2i7mBq1N3rz",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7PYTiHqL8YwQPxMH8RtHwZoPPt65oV5dhUKcdw4c5tMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "LAjAkNeQUqMzAQdiQZNmraw9Fa77vqsEMXSUdM462Nd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CTPXtmWqHEHCicwRh2Y4WMrfM8TZZsHkeiFoQNifUPZV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1335_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1335_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1335_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1335_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1335_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1335_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1336(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 423;
  test.test_number = 1336;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1336_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1336_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1336_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1336_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1336_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1336_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1337(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 440;
  test.test_number = 1337;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1337_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1337_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1337_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1337_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1337_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1337_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1338(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 507;
  test.test_number = 1338;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1338_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1338_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1338_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1338_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1338_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1338_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1339(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 501;
  test.test_number = 1339;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1339_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1339_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1339_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1339_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1339_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1339_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1340(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 349;
  test.test_number = 1340;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1340_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1340_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1340_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1340_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1340_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1340_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1341(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 402;
  test.test_number = 1341;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1341_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1341_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1341_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1341_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1341_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1341_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1342(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 614;
  test.test_number = 1342;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1342_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1342_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1342_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1342_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1342_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1342_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1343(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 288;
  test.test_number = 1343;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1343_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1343_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1343_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1343_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1343_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1343_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1344(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 374;
  test.test_number = 1344;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1344_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1344_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1344_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1344_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1344_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1344_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1345(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 609;
  test.test_number = 1345;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1345_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1345_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1345_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1345_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1345_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1345_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1346(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 482;
  test.test_number = 1346;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1346_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1346_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1346_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1346_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1346_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1346_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1347(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 459;
  test.test_number = 1347;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1347_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1347_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1347_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1347_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1347_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1347_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1348(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,114,77,87,79,26,75,122,98,62,121,83,118,89,78,125,123,61,126,106,15,124,30,128,90,24,56,103,33,116,27,2,109,127,112,117,110,76,92,108,120,82,55,111,80,105,113 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 527;
  test.test_number = 1348;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "78CBbBthbyVzayZ8HufuUYQLfKtwQZst1ordJmiGUqxZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "CR2bBXBiKrsszkKwkAzmfGMphMuVdAdYPWV8SViRJah3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BjcDvdU8j4Y8cfZZ7XdQ7TgZLJBRZoWPMxCm4CinPGcG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 10UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J4JgNJD7KM88cKBzizdoBcnFKJjnUsFcJTwUf9KwSq6H",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2wBmTv5Smvq1Tp1gxePALodKzi68LJ5KE8tmRFjYUCxG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1348_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1348_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1348_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1348_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1348_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1348_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1349(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_withdraw_stake::old_behavior";
  test.test_nonce  = 529;
  test.test_number = 1349;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 9;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "713LmJkBtGtAduiL2A1KmakMQiwjhJDoi3yF1s1giRxY",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 11UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "A3ABCJbc5bM4HXDC3juo2tLzrNpyaATDvHtdvsvBNV4A",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BJdbtmhBrPVTfHW7KX3Rvi96i2LDE1VxpiE8eqLpfRrV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 10UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "WhcrHNyjtaXwBbeGeWv5qw4bHpftpG4ZeMbCAALj8eR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BP39WwKXxrCKdbWFEbzBbJCVtoJyc2YgRpPsomQG2s7C",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_7_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_7_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_7_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_7_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1349_acc_8_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1349_acc_8_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1349_acc_8_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1349_acc_8_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1349_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1349_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
