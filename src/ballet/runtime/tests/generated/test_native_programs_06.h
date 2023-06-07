#include "../fd_tests.h"
int test_150(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 86;
  test.test_number = 150;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "JAiEgimVAdz7y1BK7piKHkebTFSQwEguN4HWVbbvDmpR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_150_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_150_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_150_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_150_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "DtsXRgow2QjurBSSvceN8JKug9fvPfZ1mKHsG649q8Qn",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_150_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_150_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_150_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_150_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_150_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_150_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_150_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_150_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_150_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_150_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_151(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,106,27,109,76,80,112,126,55,56,61,78,114,120,29,82,75,103,125,62,83,33,90,128,123,124,113,87,79,121,117,110,111,105,26,2,92,108,116,122,89,98,15,127,30,118,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 3;
  test.test_number = 151;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8dXehmsAQnSJZxWRdnEs5gF6t5vbAQ49FwnfmEdQzJNu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_151_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_151_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_151_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_151_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9sxLee3qCBrn1dvESgKNTWLtor6uw7aygy3uh4DYW1Xd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_151_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_151_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_151_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_151_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_151_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_151_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_151_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_151_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_151_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_151_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_152(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,106,27,109,76,80,112,126,55,56,61,78,114,120,29,82,75,103,125,62,83,33,90,128,123,124,113,87,79,121,117,110,111,105,26,2,92,108,116,122,89,98,15,127,30,118,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 46;
  test.test_number = 152;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8dXehmsAQnSJZxWRdnEs5gF6t5vbAQ49FwnfmEdQzJNu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_152_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_152_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_152_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_152_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9sxLee3qCBrn1dvESgKNTWLtor6uw7aygy3uh4DYW1Xd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_152_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_152_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_152_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_152_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_152_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_152_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_152_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_152_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_152_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_152_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_153(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,106,27,109,76,80,112,126,55,56,61,78,114,120,29,82,75,103,125,62,83,33,90,128,123,124,113,87,79,121,117,110,111,105,26,2,92,108,116,122,89,98,15,127,30,118,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 81;
  test.test_number = 153;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8dXehmsAQnSJZxWRdnEs5gF6t5vbAQ49FwnfmEdQzJNu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_153_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_153_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_153_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_153_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9sxLee3qCBrn1dvESgKNTWLtor6uw7aygy3uh4DYW1Xd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_153_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_153_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_153_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_153_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_153_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_153_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_153_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_153_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_153_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_153_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_154(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,106,27,109,76,80,112,126,55,56,61,78,114,120,29,82,75,103,125,62,83,33,90,128,123,124,113,87,79,121,117,110,111,105,26,2,92,108,116,122,89,98,15,127,30,118,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 115;
  test.test_number = 154;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8dXehmsAQnSJZxWRdnEs5gF6t5vbAQ49FwnfmEdQzJNu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_154_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_154_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_154_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_154_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9sxLee3qCBrn1dvESgKNTWLtor6uw7aygy3uh4DYW1Xd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_154_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_154_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_154_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_154_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_154_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_154_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_154_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_154_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_154_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_154_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_155(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 77,106,27,109,76,80,112,126,55,56,61,78,114,120,29,82,75,103,125,62,83,33,90,128,123,124,113,87,79,121,117,110,111,105,26,2,92,108,116,122,89,98,15,127,30,118,24 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_with_seed::old_behavior";
  test.test_nonce  = 142;
  test.test_number = 155;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8dXehmsAQnSJZxWRdnEs5gF6t5vbAQ49FwnfmEdQzJNu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_155_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_155_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_155_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_155_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "9sxLee3qCBrn1dvESgKNTWLtor6uw7aygy3uh4DYW1Xd",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_155_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_155_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_155_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_155_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_155_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_155_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_155_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_155_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_155_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_155_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_156(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 9;
  test.test_number = 156;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8bJPmwp2oZRARXreT4qbhyzMbC6bvG75PzdHJMPYnuJM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "12mJUDcoECxN8CkAG6oFGuzCnUPUqkViABeic3CWeA9o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GEZ4oc5AznjmmohEVFknxKa15HBgKN9VDoYZLYGyCown",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_156_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_156_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_156_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_156_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_156_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_156_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_157(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 10;
  test.test_number = 157;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FkgmhHeZmXcoG21j1dyM3n2RdQogKMApUQBDS4MBmnb7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4SM2kS44cCZkzKEs4g3tL8Bv5M1PPEagzFG6dx1SmQKW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ec6MjZWCoSRphZRR4f5o3eTAN4xyF58GXBpUYtcpgwMp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_157_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_157_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_157_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_157_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_157_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_157_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_158(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 317;
  test.test_number = 158;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8bJPmwp2oZRARXreT4qbhyzMbC6bvG75PzdHJMPYnuJM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "12mJUDcoECxN8CkAG6oFGuzCnUPUqkViABeic3CWeA9o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GEZ4oc5AznjmmohEVFknxKa15HBgKN9VDoYZLYGyCown",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_158_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_158_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_158_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_158_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_158_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_158_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_159(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 497;
  test.test_number = 159;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8bJPmwp2oZRARXreT4qbhyzMbC6bvG75PzdHJMPYnuJM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "12mJUDcoECxN8CkAG6oFGuzCnUPUqkViABeic3CWeA9o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GEZ4oc5AznjmmohEVFknxKa15HBgKN9VDoYZLYGyCown",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_159_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_159_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_159_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_159_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_159_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_159_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_160(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 256;
  test.test_number = 160;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FkgmhHeZmXcoG21j1dyM3n2RdQogKMApUQBDS4MBmnb7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4SM2kS44cCZkzKEs4g3tL8Bv5M1PPEagzFG6dx1SmQKW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ec6MjZWCoSRphZRR4f5o3eTAN4xyF58GXBpUYtcpgwMp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_160_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_160_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_160_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_160_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_160_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_160_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_161(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 500;
  test.test_number = 161;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FkgmhHeZmXcoG21j1dyM3n2RdQogKMApUQBDS4MBmnb7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4SM2kS44cCZkzKEs4g3tL8Bv5M1PPEagzFG6dx1SmQKW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ec6MjZWCoSRphZRR4f5o3eTAN4xyF58GXBpUYtcpgwMp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_161_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_161_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_161_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_161_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_161_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_161_raw_sz;
  test.expected_result = -26;
  test.custom_err = 12;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_162(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 469;
  test.test_number = 162;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8bJPmwp2oZRARXreT4qbhyzMbC6bvG75PzdHJMPYnuJM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "12mJUDcoECxN8CkAG6oFGuzCnUPUqkViABeic3CWeA9o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GEZ4oc5AznjmmohEVFknxKa15HBgKN9VDoYZLYGyCown",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_162_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_162_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_162_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_162_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_162_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_162_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_163(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 454;
  test.test_number = 163;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FkgmhHeZmXcoG21j1dyM3n2RdQogKMApUQBDS4MBmnb7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4SM2kS44cCZkzKEs4g3tL8Bv5M1PPEagzFG6dx1SmQKW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ec6MjZWCoSRphZRR4f5o3eTAN4xyF58GXBpUYtcpgwMp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_163_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_163_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_163_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_163_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_163_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_163_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_164(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 405;
  test.test_number = 164;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8bJPmwp2oZRARXreT4qbhyzMbC6bvG75PzdHJMPYnuJM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "12mJUDcoECxN8CkAG6oFGuzCnUPUqkViABeic3CWeA9o",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "GEZ4oc5AznjmmohEVFknxKa15HBgKN9VDoYZLYGyCown",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_164_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_164_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_164_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_164_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_164_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_164_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_165(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 110,109,116,114,112,124,89,103,90,29,92,105,76,15,56,106,30,79,83,123,61,27,33,62,128,82,75,125,126,111,98,55,24,122,2,80,108,127,121,117,120,118,87,26,77,113,78 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::new_behavior";
  test.test_nonce  = 383;
  test.test_number = 165;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FkgmhHeZmXcoG21j1dyM3n2RdQogKMApUQBDS4MBmnb7",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4SM2kS44cCZkzKEs4g3tL8Bv5M1PPEagzFG6dx1SmQKW",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Ec6MjZWCoSRphZRR4f5o3eTAN4xyF58GXBpUYtcpgwMp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_165_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_165_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_165_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_165_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_165_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_165_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_166(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 7;
  test.test_number = 166;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5Lq46ZH9XNgQo6moXgqzg58bhn5KPeVFtgAZG26CjB5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "79XA8mK44YkFq12FRtUhBXucz3uJas4bTXqobsqeNtEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4jSnxN1WnirAHr5aHgbwbjQ5YywgVtCWhRfVhvDJ9zVw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_166_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_166_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_166_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_166_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_166_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_166_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_167(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 87,89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 9;
  test.test_number = 167;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbtPDSVbFhUgqXj8JuyJeJVAXXkHkPAva1wqmqGy3B9y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J87xaTQiv1yASxBPJbYxM9zs6uXM9e85WmrpVG1WTyEK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8CSZY2UGYBkQ2opshvLC96UbXGei8NRKsYxU53tsG2A2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_167_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_167_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_167_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_167_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_167_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_167_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_168(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 87,89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 329;
  test.test_number = 168;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbtPDSVbFhUgqXj8JuyJeJVAXXkHkPAva1wqmqGy3B9y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J87xaTQiv1yASxBPJbYxM9zs6uXM9e85WmrpVG1WTyEK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8CSZY2UGYBkQ2opshvLC96UbXGei8NRKsYxU53tsG2A2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_168_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_168_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_168_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_168_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_168_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_168_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_169(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 87,89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 539;
  test.test_number = 169;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbtPDSVbFhUgqXj8JuyJeJVAXXkHkPAva1wqmqGy3B9y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J87xaTQiv1yASxBPJbYxM9zs6uXM9e85WmrpVG1WTyEK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8CSZY2UGYBkQ2opshvLC96UbXGei8NRKsYxU53tsG2A2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_169_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_169_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_169_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_169_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_169_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_169_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_170(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 358;
  test.test_number = 170;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5Lq46ZH9XNgQo6moXgqzg58bhn5KPeVFtgAZG26CjB5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "79XA8mK44YkFq12FRtUhBXucz3uJas4bTXqobsqeNtEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4jSnxN1WnirAHr5aHgbwbjQ5YywgVtCWhRfVhvDJ9zVw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_170_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_170_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_170_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_170_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_170_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_170_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_171(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 480;
  test.test_number = 171;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5Lq46ZH9XNgQo6moXgqzg58bhn5KPeVFtgAZG26CjB5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "79XA8mK44YkFq12FRtUhBXucz3uJas4bTXqobsqeNtEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4jSnxN1WnirAHr5aHgbwbjQ5YywgVtCWhRfVhvDJ9zVw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_171_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_171_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_171_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_171_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_171_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_171_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_172(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 87,89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 484;
  test.test_number = 172;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbtPDSVbFhUgqXj8JuyJeJVAXXkHkPAva1wqmqGy3B9y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J87xaTQiv1yASxBPJbYxM9zs6uXM9e85WmrpVG1WTyEK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8CSZY2UGYBkQ2opshvLC96UbXGei8NRKsYxU53tsG2A2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_172_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_172_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_172_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_172_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_172_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_172_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_173(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 24,122,98,90,82,30,124,79,106,33,117,121,112,105,108,62,61,27,87,128,109,75,77,56,120,113,118,92,110,78,29,15,83,111,123,76,126,127,26,103,125,80,55,116,2,89,114 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 436;
  test.test_number = 173;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5Lq46ZH9XNgQo6moXgqzg58bhn5KPeVFtgAZG26CjB5e",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "79XA8mK44YkFq12FRtUhBXucz3uJas4bTXqobsqeNtEZ",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "4jSnxN1WnirAHr5aHgbwbjQ5YywgVtCWhRfVhvDJ9zVw",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_173_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_173_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_173_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_173_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_173_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_173_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_174(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 2;
  uchar disabled_features[] = { 87,89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_behavior_withdrawal_then_redelegate_with_less_than_minimum_stake_delegation::old_old_behavior";
  test.test_nonce  = 416;
  test.test_number = 174;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HbtPDSVbFhUgqXj8JuyJeJVAXXkHkPAva1wqmqGy3B9y",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "J87xaTQiv1yASxBPJbYxM9zs6uXM9e85WmrpVG1WTyEK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8CSZY2UGYBkQ2opshvLC96UbXGei8NRKsYxU53tsG2A2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_174_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_174_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_174_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_174_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_174_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_174_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
