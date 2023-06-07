#include "../fd_tests.h"
int test_1225(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 503;
  test.test_number = 1225;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111127nR7XUzPK3c4fnSwwYdK5BpfLDUsThv7vX",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1225_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1225_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1225_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1225_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1225_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1225_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1225_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1225_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111128BkiWbHg2E4wVDb2xxxdZK6SxijpAwVxEs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1225_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1225_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1225_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1225_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1225_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1225_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1226(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 546;
  test.test_number = 1226;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111126yjuZGPotggK2vAmthxg6wH65Cxz3EkTHq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1226_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1226_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1226_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1226_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1226_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1226_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1226_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1226_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111126aQJaA6XBWDSDV2gsHdMcp1JShi3L1AcyV",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1226_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1226_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1226_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1226_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1226_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1226_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1227(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 508;
  test.test_number = 1227;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111129PmXTvBY9mTZwX1J3Dxb1guorEWeJeFTBu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1227_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1227_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1227_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1227_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1227_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1227_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1227_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1227_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111128zRvUotFSazh85sD1odGXZe2DjFhbQfcsZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1227_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1227_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1227_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1227_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1227_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1227_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1228(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 369;
  test.test_number = 1228;
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
  test_acc->data            = fd_flamenco_native_prog_test_1228_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1228_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1228_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1228_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1228_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1228_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1228_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1228_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1228_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1228_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1228_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1228_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111jepwNWbYG87sgwnBbUJnQHrPiUJzMpqJXZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1228_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1228_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1228_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1228_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111jFVLPQJFYwezsWe6a3yTvAac5y43ebFUDD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1228_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1228_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1228_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1228_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1228_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1228_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1229(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 294;
  test.test_number = 1229;
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
  test_acc->data            = fd_flamenco_native_prog_test_1229_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1229_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1229_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1229_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111epmhZD25jxZMsk79JSJxanaxARDfq1qJjR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1229_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1229_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1229_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1229_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111eRS6a6io2n6V4Jy4H1ye6fKAXuxj7nFUR5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1229_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1229_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1229_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1229_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1229_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1229_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1229_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1229_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1229_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1229_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1229_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1229_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1229_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1229_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1230(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 553;
  test.test_number = 1230;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1230_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1230_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1230_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1230_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1230_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1230_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1230_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1230_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111129PmXTvBY9mTZwX1J3Dxb1guorEWeJeFTBu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1230_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1230_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1230_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1230_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111128zRvUotFSazh85sD1odGXZe2DjFhbQfcsZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1230_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1230_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1230_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1230_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1230_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1230_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1231(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 565;
  test.test_number = 1231;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112Boo9NZyGQrEpr7qpBjxVvSYXdG4Ja3kT5y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1231_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1231_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1231_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1231_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112B17wQMNgzVK5DFZe8uHrxBzxNFYR9aanTH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1231_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1231_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1231_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1231_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1231_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1231_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1231_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1231_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1231_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1231_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1231_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1231_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1231_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1231_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1232(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 576;
  test.test_number = 1232;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112EDpmHDkzfw25kigLLFxQqCBFQHbxqTFSz3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1232_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1232_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1232_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1232_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1232_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1232_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1232_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1232_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1232_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1232_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1232_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1232_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1232_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1232_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1233(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 514;
  test.test_number = 1233;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1233_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1233_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1233_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1233_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112AbnLRF5QHJrCPpRZ7UxYU4jAjkHUSLzx8w",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1233_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1233_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1233_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1233_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112B17wQMNgzVK5DFZe8uHrxBzxNFYR9aanTH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1233_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1233_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1233_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1233_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1233_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1233_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1233_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1233_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1233_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1233_raw_sz;
  test.expected_result = -7;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1234(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 518;
  test.test_number = 1234;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1234_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1234_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1234_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1234_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1234_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1234_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1234_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1234_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112CcUMLnZqqDAaUz7zEad8th66tGaBzWv7if",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1234_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1234_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1234_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1234_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx31",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1234_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1234_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1234_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1234_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1234_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1234_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1235(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 127,122,33,118,79,125,82,116,120,110,90,2,75,80,113,103,83,56,87,61,108,111,98,62,55,124,26,128,29,112,27,126,105,89,121,117,76,78,106,114,109,15,92,24,30,123,77 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::new_behavior";
  test.test_nonce  = 520;
  test.test_number = 1235;
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
  test_acc->data            = fd_flamenco_native_prog_test_1235_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1235_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1235_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1235_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112DR9ZK1ARFa6L7rQAHRHmrwdg9H65Qz5nMM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1235_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1235_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1235_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1235_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1235_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1235_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1235_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1235_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1235_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1235_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1236(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 196;
  test.test_number = 1236;
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
  test_acc->data            = fd_flamenco_native_prog_test_1236_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1236_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1236_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1236_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Skdc1x5SSYf5LjvYZrKQ32RMHHVNVzLKF5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1236_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1236_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1236_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1236_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1236_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1236_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1236_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1236_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1236_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1236_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1237(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 261;
  test.test_number = 1237;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1237_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1237_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1237_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1237_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1237_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1237_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1237_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1237_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Skdc1x5SSYf5LjvYZrKQ32RMHHVNVzLKF5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1237_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1237_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1237_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1237_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1237_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1237_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1238(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 212;
  test.test_number = 1238;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111bCjGhELVMLPUWqrN5fK6Df8sVsuBRuaotK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1238_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1238_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1238_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1238_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111aoPfi83Ce9vbhQiH4EymjXs5sNeEifzyZy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1238_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1238_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1238_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1238_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1238_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1238_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1238_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1238_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1238_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1238_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1239(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 295;
  test.test_number = 1239;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111c1QUfSw4mhKE9i8Y8VyjBugSktR4rNkUX1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1239_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1239_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1239_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1239_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1239_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1239_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1239_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1239_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111cQk5eZEMUsn6y9Gd9vK3g2xEPPg1ZcLJqM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1239_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1239_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1239_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1239_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1239_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1239_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1240(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 407;
  test.test_number = 1240;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1240_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1240_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1240_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1240_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111qgtz994ruq51xSsUxmJZgAwCA3B92LaoGj",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1240_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1240_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1240_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1240_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1240_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1240_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1240_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1240_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1240_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1240_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1240_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1240_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111qHZPA2maCec991jPwLyFC3fQXXvCK6zxxP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1240_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1240_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1240_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1240_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1240_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1240_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1240_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1240_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1240_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1240_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1241(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 450;
  test.test_number = 1241;
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
  test_acc->data            = fd_flamenco_native_prog_test_1241_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1241_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1241_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1241_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111tWGD2u9st6K9gUr68hdo53qhZZyjzyfdV9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1241_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1241_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1241_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1241_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111t6vc3nrbAurGs3i17HJUavZuw4ioHk5oAo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1241_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1241_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1241_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1241_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1241_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1241_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1241_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1241_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1241_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1241_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1241_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1241_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1241_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1241_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1241_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1241_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1241_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1241_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1242(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 240;
  test.test_number = 1242;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1242_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1242_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1242_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1242_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111cp5gdfXeC4EynaQiBLeNAAE21tvxGqv99h",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1242_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1242_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1242_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1242_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1242_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1242_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1242_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1242_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111dDRHcmpvuEhrc1YoCkygeHVoeQBtz5VyU3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1242_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1242_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1242_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1242_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1242_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1242_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1243(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 397;
  test.test_number = 1243;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111oGsNEVH8ekHm3r2xpFJemRJUP1dUkw5oNf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1243_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1243_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1243_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1243_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111nsXmFNyqwZptEQtsnpyLHJ2gkWNY3hVy4K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1243_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1243_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1243_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1243_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1243_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1243_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1243_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1243_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1243_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1243_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1243_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1243_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1243_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1243_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1244(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 325;
  test.test_number = 1244;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111fE7JYKKNT92EhBFEKreH4urjnvUcYFR93m",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1244_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1244_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1244_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1244_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111fdSuXRcfAKV7WcPKMGybZ38XRRjZFUzyN7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1244_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1244_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1244_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1244_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1244_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1244_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1244_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1244_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1244_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1244_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1244_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1244_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1244_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1244_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1245(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 427;
  test.test_number = 1245;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111oGsNEVH8ekHm3r2xpFJemRJUP1dUkw5oNf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1245_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1245_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1245_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1245_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadStake11111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1245_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1245_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1245_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1245_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111nsXmFNyqwZptEQtsnpyLHJ2gkWNY3hVy4K",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1245_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1245_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1245_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1245_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1245_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1245_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1245_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1245_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1245_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1245_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1246(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 440;
  test.test_number = 1246;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111vvHpwYwc9B6Qb5gcHDdhyoURLbXQGPAdPD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1246_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1246_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1246_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1246_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1246_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1246_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1246_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1246_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1246_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1246_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1246_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1246_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111wiy2umYBZY2ADwxnL4JLx41zbc3HgrLJ1u",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1246_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1246_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1246_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1246_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111wKdRvfEtrMZHQWphJdy2TvkCy6nLyckThZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1246_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1246_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1246_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1246_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1246_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1246_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1247(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 502;
  test.test_number = 1247;
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
  test_acc->data            = fd_flamenco_native_prog_test_1247_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1247_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1247_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1247_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111xvyqs6S3h5QngFP3QKJJQRqMV7p7pZ5nxw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1247_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1247_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1247_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1247_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111yjf3qK2d7SLYK7fDT9xwNgNvk8L1F2FTbd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1247_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1247_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1247_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1247_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1247_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1247_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1247_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1247_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111yLKSrCjLQFsfVgX8RjdctZ797d54XnfdHH",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1247_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1247_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1247_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1247_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1247_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1247_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1248(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 472;
  test.test_number = 1248;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111zwfrndvVEyjAmR5UXQxtq4CHde6qNizxYf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1248_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1248_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1248_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1248_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1248_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1248_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1248_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1248_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111121M1TmkDmxAC3arDZYqJDKBU5G9Mn5xans1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1248_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1248_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1248_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1248_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1248_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1248_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1249(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,87,79,83,112,113,33,98,61,109,76,75,30,55,108,110,117,92,128,24,120,103,26,114,106,89,122,78,29,126,82,118,56,62,80,15,27,125,111,105,124,77,123,90,127,2,121 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_stake_process_instruction::old_behavior";
  test.test_nonce  = 531;
  test.test_number = 1249;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "111111124ZiHecc5dbu48KLFkBxmCBeNJBRKmqFTPm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1249_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1249_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1249_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1249_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "111111124y3tdiuNLnMvwkULmcJ5gJv9vggGV4qHi7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1249_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1249_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1249_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1249_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1249_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1249_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1249_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1249_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1249_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1249_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
