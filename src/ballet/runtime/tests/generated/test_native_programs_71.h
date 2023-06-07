#include "../fd_tests.h"
int test_1775(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 92,114,112,30,122,127,82,75,87,61,80,105,27,106,62,124,126,79,110,108,109,24,77,15,120,103,121,26,117,123,98,125,90,116,33,29,89,55,111,76,2,83,78,113,128,56,118 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 53;
  test.test_number = 1775;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1775_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1775_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1775_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1775_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1775_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1775_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1775_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1775_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1775_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1775_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1775_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1775_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1775_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1775_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1776(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 79,105,111,113,98,106,15,90,77,61,78,24,27,62,128,55,82,87,2,33,117,83,112,29,116,124,89,92,114,75,126,125,80,123,121,110,56,108,30,26,109,103,120,76,122,118,127 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 42;
  test.test_number = 1776;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JhsYKn7gEwPYz58p5Tf2LWychCLWHJfevB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1776_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1776_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1776_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1776_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1776_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1776_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1776_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1776_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KutMH71YNUnBSNZ59ieyntnyai7LR1R9sD",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1776_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1776_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1776_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1776_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1776_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1776_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_1777(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 79,105,111,113,98,106,15,90,77,61,78,24,27,62,128,55,82,87,2,33,117,83,112,29,116,124,89,92,114,75,126,125,80,123,121,110,56,108,30,26,109,103,120,76,122,118,127 };
  test.disable_feature = disabled_features;
  test.test_name = "vote_processor::tests::test_withdrawer_base_key_can_authorize_new_withdrawer";
  test.test_nonce  = 41;
  test.test_number = 1777;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1777_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1777_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1777_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1777_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1777_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1777_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1777_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1777_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_1777_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_1777_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_1777_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_1777_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_1777_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_1777_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
