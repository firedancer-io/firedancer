#include "../fd_tests.h"
int test_1625(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,127,83,105,114,79,87,128,75,126,110,121,77,30,82,98,103,109,111,108,124,29,27,55,116,24,120,106,2,56,90,125,76,62,122,123,113,112,15,26,61,80,33,92,117,89,78 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_spoofed_vote";
  test.test_nonce  = 0;
  test.test_number = 1625;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1625_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1625_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1625_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1625_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1625_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1625_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1625_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1625_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1625_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1625_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1625_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1625_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1625_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1625_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1625_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1625_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1625_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1625_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1625_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1625_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1625_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1625_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1625_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1625_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1625_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1625_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1626(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,118,77,90,105,122,87,26,79,15,83,98,108,121,124,78,89,116,112,80,30,117,2,120,33,111,92,114,56,128,29,24,113,55,106,123,109,127,61,82,126,110,27,76,125,103,62 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_spoofed_vote";
  test.test_nonce  = 44;
  test.test_number = 1626;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1626_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1626_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1626_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1626_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1626_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1626_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1626_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1626_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1626_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1626_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1626_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1626_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1626_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1626_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1626_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1626_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1626_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1626_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1626_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1626_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1626_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1626_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1626_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1626_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1626_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1626_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1627(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 75,118,77,90,105,122,87,26,79,15,83,98,108,121,124,78,89,116,112,80,30,117,2,120,33,111,92,114,56,128,29,24,113,55,106,123,109,127,61,82,126,110,27,76,125,103,62 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_spoofed_vote";
  test.test_nonce  = 46;
  test.test_number = 1627;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1627_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1627_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1627_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1627_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1627_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1627_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1627_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1627_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "BadVote111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1627_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1627_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1627_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1627_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1627_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1627_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1627_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1627_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1627_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1627_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1627_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1627_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1627_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1627_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1627_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1627_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1627_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1627_raw_sz;
  test.expected_result = -47;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1628(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 83,29,55,125,82,114,92,122,124,56,111,89,80,128,126,75,113,62,106,127,24,30,120,123,87,26,33,2,110,78,118,108,79,117,121,116,76,103,77,90,98,105,112,109,15,27,61 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 2;
  test.test_number = 1628;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1628_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1628_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1628_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1628_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1628_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1628_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1628_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1628_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1628_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1628_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1628_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1628_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1628_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1628_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1628_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1628_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1628_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1628_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1628_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1628_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1628_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1628_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1629(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 75,87,110,113,112,80,122,126,89,108,2,92,123,62,128,103,127,114,76,27,30,105,82,98,15,29,79,116,124,33,120,26,24,77,125,117,83,111,78,61,121,90,56,106,55,118,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 82;
  test.test_number = 1629;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1629_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1629_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1629_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1629_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1629_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1629_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1629_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1629_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1629_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1629_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1629_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1629_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1629_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1629_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1629_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1629_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1629_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1629_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1630(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 62,112,123,92,126,125,33,15,124,103,26,78,76,27,116,127,90,77,118,29,55,122,56,80,128,89,114,83,98,2,87,113,117,75,121,24,82,120,106,111,110,105,79,61,30,108,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 68;
  test.test_number = 1630;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1630_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1630_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1630_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1630_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1630_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1630_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1631(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,112,123,92,126,125,33,15,124,103,26,78,76,27,116,127,90,77,118,29,55,122,56,80,128,89,114,83,98,2,87,113,117,75,121,24,82,120,106,111,110,105,79,61,30,108,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 2;
  test.test_number = 1631;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 5;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1631_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1631_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1631_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1631_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1631_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1631_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1631_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1631_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1631_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1631_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1631_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1631_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1631_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1631_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1631_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1631_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1631_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1631_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1631_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1631_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1631_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1631_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1632(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,112,123,92,126,125,33,15,124,103,26,78,76,27,116,127,90,77,118,29,55,122,56,80,128,89,114,83,98,2,87,113,117,75,121,24,82,120,106,111,110,105,79,61,30,108,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 71;
  test.test_number = 1632;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1632_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1632_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1632_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1632_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1632_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1632_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1633(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 62,112,123,92,126,125,33,15,124,103,26,78,76,27,116,127,90,77,118,29,55,122,56,80,128,89,114,83,98,2,87,113,117,75,121,24,82,120,106,111,110,105,79,61,30,108,109 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 83;
  test.test_number = 1633;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1633_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1633_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1633_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1633_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1633_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1633_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1633_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1633_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1633_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1633_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1633_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1633_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1633_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1633_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1633_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1633_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1633_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1633_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1634(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,77,114,117,56,113,125,106,83,118,89,116,29,76,122,105,127,120,26,111,78,128,15,55,110,124,103,61,27,30,121,80,92,112,82,24,123,79,108,33,98,90,109,75,62,87,126 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 78;
  test.test_number = 1634;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1634_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1634_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1634_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1634_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1634_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1634_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1635(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 122,110,125,83,112,118,121,27,2,90,108,89,127,124,56,92,117,109,55,61,15,120,98,111,79,103,87,62,33,24,123,29,30,76,75,126,114,113,82,77,80,116,26,106,78,105,128 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 83;
  test.test_number = 1635;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1635_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1635_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1635_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1635_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1635_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1635_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1635_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1635_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1635_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1635_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1635_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1635_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1635_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1635_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1635_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1635_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1635_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1635_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1636(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,29,116,127,124,120,105,83,126,118,128,15,98,113,122,27,106,89,33,75,103,26,82,108,62,55,80,78,111,2,92,61,24,121,110,112,90,79,76,123,30,77,125,114,117,109,87 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 36;
  test.test_number = 1636;
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
  test_acc->data            = fd_flamenco_native_prog_test_1636_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1636_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1636_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1636_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1636_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1636_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1636_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1636_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1636_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1636_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1636_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1636_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1636_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1636_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1636_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1636_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111QLbz7JHiBTspS962RLKV8GndWFwiEaqKM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1636_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1636_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1636_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1636_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1636_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1636_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1637(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,29,116,127,124,120,105,83,126,118,128,15,98,113,122,27,106,89,33,75,103,26,82,108,62,55,80,78,111,2,92,61,24,121,110,112,90,79,76,123,30,77,125,114,117,109,87 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 45;
  test.test_number = 1637;
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
  test_acc->data            = fd_flamenco_native_prog_test_1637_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1637_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1637_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1637_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1637_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1637_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1637_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1637_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1637_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1637_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1637_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1637_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1637_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1637_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1637_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1637_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1637_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1637_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1637_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1637_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1637_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1637_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1638(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,29,116,127,124,120,105,83,126,118,128,15,98,113,122,27,106,89,33,75,103,26,82,108,62,55,80,78,111,2,92,61,24,121,110,112,90,79,76,123,30,77,125,114,117,109,87 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 80;
  test.test_number = 1638;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112D1oxKts8YPdTJRG5FzxTNpMtWmq8hkVx3",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1638_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1638_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1638_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1638_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1638_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1638_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1639(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,29,116,127,124,120,105,83,126,118,128,15,98,113,122,27,106,89,33,75,103,26,82,108,62,55,80,78,111,2,92,61,24,121,110,112,90,79,76,123,30,77,125,114,117,109,87 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_authorize_checked";
  test.test_nonce  = 85;
  test.test_number = 1639;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 4;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111ogCyDbaRMvkdsHB3qfdyFYaG1WtRUAfdh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1639_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1639_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1639_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1639_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1639_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1639_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1639_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1639_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111YnhenaYm6FcDcF1qw9KBJuW9irMXAW5ozF",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1639_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1639_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1639_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1639_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111112cMQwSC9qirWGjZM6gLGwW69X22mqwLLGP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111ZC3Fmgr3oS56Rg9vxZeVo2mwMMcTsjfeJb",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1639_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1639_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1639_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1639_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1639_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1639_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1640(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,15,110,75,106,61,27,80,123,29,24,103,78,118,33,98,26,56,82,126,62,105,117,2,121,76,128,122,127,77,30,55,111,89,109,83,116,113,90,114,124,108,125,120,79,87,112 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction_decode_bail";
  test.test_nonce  = 0;
  test.test_number = 1640;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1640_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1640_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1641(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 92,15,110,75,106,61,27,80,123,29,24,103,78,118,33,98,26,56,82,126,62,105,117,2,121,76,128,122,127,77,30,55,111,89,109,83,116,113,90,114,124,108,125,120,79,87,112 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction_decode_bail";
  test.test_nonce  = 1;
  test.test_number = 1641;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 0;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1641_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1641_raw_sz;
  test.expected_result = -20;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1642(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 118,92,120,116,79,114,61,111,113,33,55,121,15,56,27,123,83,30,62,117,2,103,108,109,87,77,78,106,125,90,82,127,26,105,80,29,126,112,24,124,89,76,128,110,122,75,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 12;
  test.test_number = 1642;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1642_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1642_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1642_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1642_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1642_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1642_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1642_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1642_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1642_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1642_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1642_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1642_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1642_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1642_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1642_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1642_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1642_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1642_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1642_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1642_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1642_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1642_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1642_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1642_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1642_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1642_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1643(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 118,92,120,116,79,114,61,111,113,33,55,121,15,56,27,123,83,30,62,117,2,103,108,109,87,77,78,106,125,90,82,127,26,105,80,29,126,112,24,124,89,76,128,110,122,75,98 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 3;
  test.test_number = 1643;
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
  test_acc->data            = fd_flamenco_native_prog_test_1643_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1643_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1643_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1643_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111113R2cuenjG5nFubqX9Wzuukdin2YfGQVzu5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1643_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1643_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1643_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1643_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1643_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1643_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1643_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1643_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1643_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1643_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1643_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1643_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1643_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1643_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1643_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1643_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1643_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1643_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1643_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1643_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1643_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1643_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1644(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 55,29,33,123,114,105,112,110,2,118,83,125,108,87,24,109,126,103,62,27,111,116,117,78,76,80,106,82,124,98,127,56,120,30,61,79,128,121,122,26,89,75,77,113,15,92,90 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 81;
  test.test_number = 1644;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1644_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1644_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1644_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1644_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1644_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1644_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1644_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1644_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1644_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1644_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1644_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1644_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1644_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1644_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1644_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1644_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Xz2SpMxBftgTyNjftJeYLexaTqqdk2v9MZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1644_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1644_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1644_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1644_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1644_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1644_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1644_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1644_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1644_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1644_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1645(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 55,29,33,123,114,105,112,110,2,118,83,125,108,87,24,109,126,103,62,27,111,116,117,78,76,80,106,82,124,98,127,56,120,30,61,79,128,121,122,26,89,75,77,113,15,92,90 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 81;
  test.test_number = 1645;
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
  test_acc->data            = fd_flamenco_native_prog_test_1645_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1645_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1645_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1645_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1645_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1645_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1645_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1645_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1645_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1645_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1645_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1645_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1645_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1645_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1645_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1645_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111XagqqFetxiDb9wbartKDrXgnqLah2oLK3D",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1645_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1645_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1645_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1645_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Xz2SpMxBftgTyNjftJeYLexaTqqdk2v9MZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1645_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1645_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1645_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1645_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1645_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1645_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1646(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 29,75,87,113,80,126,125,62,78,111,106,112,118,108,27,128,89,79,109,127,30,121,124,77,61,103,33,90,2,56,120,92,110,117,122,15,76,114,24,26,82,83,116,123,105,98,55 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 56;
  test.test_number = 1646;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1646_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1646_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1646_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1646_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111VyLRtpTk7zN5tD3EmCywv2beKKYvBrzymq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1646_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1646_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1646_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1646_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111WNg2svm2qApxheBKndKGQ9sRwporu6ap6B",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1646_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1646_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1646_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1646_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1646_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1646_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1646_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1646_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1646_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1646_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1646_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1646_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1646_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1646_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1646_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1646_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1646_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1646_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1647(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 29,75,87,113,80,126,125,62,78,111,106,112,118,108,27,128,89,79,109,127,30,121,124,77,61,103,33,90,2,56,120,92,110,117,122,15,76,114,24,26,82,83,116,123,105,98,55 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 49;
  test.test_number = 1647;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 6;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111VAfDvbsAhdSLFLm4iNKJwn454K32mPqK99",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1647_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1647_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1647_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1647_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1647_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1647_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1647_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1647_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1647_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1647_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1647_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1647_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1647_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1647_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1647_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1647_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1647_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1647_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1647_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1647_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111UmKcwVZszSyTRucygwyzTenHRon64AFUpo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1647_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1647_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1647_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1647_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1647_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1647_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1648(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 89,2,30,79,126,77,114,121,83,112,33,116,125,26,109,98,24,56,87,62,75,61,128,55,122,123,111,15,106,120,90,105,127,103,27,118,80,82,29,108,78,110,117,76,113,124,92 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 91;
  test.test_number = 1648;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111cQk5eZEMUsn6y9Gd9vK3g2xEPPg1ZcLJqM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111bc4sgLdn4WrMLGzT75eQhnQf8PA899AeCf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111c1QUfSw4mhKE9i8Y8VyjBugSktR4rNkUX1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1648_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1648_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1648_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1648_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1648_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1648_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1649(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 89,2,30,79,126,77,114,121,83,112,33,116,125,26,109,98,24,56,87,62,75,61,128,55,122,123,111,15,106,120,90,105,127,103,27,118,80,82,29,108,78,110,117,76,113,124,92 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_vote_process_instruction";
  test.test_nonce  = 91;
  test.test_number = 1649;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111cQk5eZEMUsn6y9Gd9vK3g2xEPPg1ZcLJqM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarS1otHashes111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111bc4sgLdn4WrMLGzT75eQhnQf8PA899AeCf",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111c1QUfSw4mhKE9i8Y8VyjBugSktR4rNkUX1",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarEpochSchedu1e111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1649_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1649_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1649_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1649_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1649_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1649_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
