#include "../fd_tests.h"
int test_50(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 103,118,56,120,15,62,126,61,77,87,112,83,98,116,122,125,128,121,90,2,124,78,89,117,76,80,111,127,106,92,123,79,105,29,113,114,24,26,82,55,109,75,27,30,108,33,110 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_additional_signers";
  test.test_nonce  = 9;
  test.test_number = 50;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8X8iecVr3B5QvZFdZ9EqZE5k7AngKDqN5tNHkRw2S2yu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_50_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_50_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_50_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_50_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_50_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_50_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_51(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 103,118,56,120,15,62,126,61,77,87,112,83,98,116,122,125,128,121,90,2,124,78,89,117,76,80,111,127,106,92,123,79,105,29,113,114,24,26,82,55,109,75,27,30,108,33,110 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_additional_signers";
  test.test_nonce  = 11;
  test.test_number = 51;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DbmcVJFtBFpjKhJxAN7wJuqzBPtmwXgGQHK7Gr469LHP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_51_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_51_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_51_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_51_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_51_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_51_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_52(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,109,128,105,76,124,78,80,89,33,82,29,27,83,123,118,77,15,56,79,87,125,98,26,108,30,55,75,112,62,126,103,92,116,111,24,61,113,110,117,127,120,106,2,122,121,114 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_additional_signers";
  test.test_nonce  = 21;
  test.test_number = 52;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "8X8iecVr3B5QvZFdZ9EqZE5k7AngKDqN5tNHkRw2S2yu",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_52_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_52_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_52_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_52_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FVAiSujNZVgYSc27t6zUTWoKfAGxbRzzPR",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_52_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_52_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_52_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_52_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_52_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_52_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_52_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_52_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_52_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_52_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_53(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,109,128,105,76,124,78,80,89,33,82,29,27,83,123,118,77,15,56,79,87,125,98,26,108,30,55,75,112,62,126,103,92,116,111,24,61,113,110,117,127,120,106,2,122,121,114 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_additional_signers";
  test.test_nonce  = 24;
  test.test_number = 53;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DbmcVJFtBFpjKhJxAN7wJuqzBPtmwXgGQHK7Gr469LHP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_53_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_53_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_53_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_53_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111FtWKS22fGg9RG3ACuXKnwe57HfXuJfaphm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LKDxGDJq5fF4FohAB8zJH24mDDNH8EzzBZ",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_53_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_53_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_53_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_53_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111GHqvR8KwyrcJ5UJHvwf7RmLtvAnr1uAf27",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111LiZZFKc7nqhw5EqFCZKcm9LYqidDqUapVu",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_53_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_53_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_53_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_53_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_53_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_53_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_54(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,126,123,106,80,118,110,29,75,61,33,2,56,27,24,128,112,87,76,30,79,92,98,55,83,125,109,15,120,103,89,82,62,78,105,116,114,108,77,111,90,127,124,26,117,122,121 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_bad_additional_signer";
  test.test_nonce  = 7;
  test.test_number = 54;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GRjwK87aG4sGtuvxTvhddzZuyPzXcLH56EUSmbFqZuLG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_54_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_54_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_54_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_54_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_54_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_54_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_55(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,126,123,106,80,118,110,29,75,61,33,2,56,27,24,128,112,87,76,30,79,92,98,55,83,125,109,15,120,103,89,82,62,78,105,116,114,108,77,111,90,127,124,26,117,122,121 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_bad_additional_signer";
  test.test_nonce  = 8;
  test.test_number = 55;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RgqLcFcLWfLzuk1RfjpZ2QUNJaGcRPcSLDx2jT1tHgx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_55_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_55_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_55_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_55_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_55_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_55_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_56(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,76,89,105,92,125,79,106,98,128,124,118,121,111,24,26,82,127,15,77,120,110,126,29,112,33,108,117,2,114,109,113,87,75,56,78,83,90,62,27,55,122,123,80,30,116,103 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_bad_additional_signer";
  test.test_nonce  = 28;
  test.test_number = 56;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GRjwK87aG4sGtuvxTvhddzZuyPzXcLH56EUSmbFqZuLG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_56_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_56_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_56_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_56_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_56_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_56_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_56_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_56_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_56_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_56_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_57(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,125,110,123,30,33,108,109,2,89,116,118,24,26,90,105,117,103,15,128,80,83,120,112,121,122,82,98,87,62,56,78,75,113,76,55,29,124,61,79,27,127,77,111,126,92,114 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_bad_additional_signer";
  test.test_nonce  = 20;
  test.test_number = 57;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "GRjwK87aG4sGtuvxTvhddzZuyPzXcLH56EUSmbFqZuLG",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_57_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_57_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_57_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_57_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_57_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_57_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_57_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_57_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_57_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_57_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_58(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,125,110,123,30,33,108,109,2,89,116,118,24,26,90,105,117,103,15,128,80,83,120,112,121,122,82,98,87,62,56,78,75,113,76,55,29,124,61,79,27,127,77,111,126,92,114 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_bad_additional_signer";
  test.test_nonce  = 21;
  test.test_number = 58;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RgqLcFcLWfLzuk1RfjpZ2QUNJaGcRPcSLDx2jT1tHgx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_58_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_58_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_58_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_58_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111HVrjNTDp7PzvXmiZ1Cf4t9AFogZg9bv9y9",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111JJXwLfpPXkvgAdzj43KhrPhq4h5Za55pbq",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_58_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_58_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_58_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_58_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_58_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_58_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_59(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,125,110,123,30,33,108,109,2,89,116,118,24,26,90,105,117,103,15,128,80,83,120,112,121,122,82,98,87,62,56,78,75,113,76,55,29,124,61,79,27,127,77,111,126,92,114 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_with_bad_additional_signer";
  test.test_nonce  = 26;
  test.test_number = 59;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "RgqLcFcLWfLzuk1RfjpZ2QUNJaGcRPcSLDx2jT1tHgx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_59_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_59_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_59_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_59_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111H6X8PLvXQDY3iLaTynKkQ1tUBBJjSNLKeo",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111HuCLMZX6paToMCre2czPNGS3SBpcrqVzHV",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_59_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_59_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_59_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_59_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_59_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_59_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_60(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 27,116,90,80,108,33,111,98,82,109,118,126,89,56,77,103,15,124,24,105,117,128,79,61,78,29,123,92,62,76,125,112,55,75,26,106,30,110,2,114,83,113,121,122,120,127,87 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_without_config_signer";
  test.test_nonce  = 10;
  test.test_number = 60;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "HMmG6gZunubSCn4SttEYgREhRcHDgAX5gYhDrxXkYU4R",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_60_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_60_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_60_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_60_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_60_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_60_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_61(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 27,116,90,80,108,33,111,98,82,109,118,126,89,56,77,103,15,124,24,105,117,128,79,61,78,29,123,92,62,76,125,112,55,75,26,106,30,110,2,114,83,113,121,122,120,127,87 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_without_config_signer";
  test.test_nonce  = 9;
  test.test_number = 61;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "UZAj8wEZGTG6MhNYgq1K5DPnYsXXyjTKFCWN8oEucJe",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_61_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_61_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_61_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_61_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_61_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_61_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_62(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,117,26,80,106,56,116,76,2,79,27,105,55,127,61,126,112,109,92,103,113,78,118,89,62,122,98,124,87,125,29,120,114,75,30,82,121,15,24,110,33,123,128,90,77,111,83 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_without_config_signer";
  test.test_nonce  = 23;
  test.test_number = 62;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_62_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_62_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_62_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_62_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_62_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_62_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_63(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,117,26,80,106,56,116,76,2,79,27,105,55,127,61,126,112,109,92,103,113,78,118,89,62,122,98,124,87,125,29,120,114,75,30,82,121,15,24,110,33,123,128,90,77,111,83 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_without_config_signer";
  test.test_nonce  = 23;
  test.test_number = 63;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "1111111KWYkHziFfJKJcwQz8JKfJmXBxCrPhmqKYs",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_63_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_63_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_63_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_63_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_63_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_63_raw_sz;
  test.expected_result = -4;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_64(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 385;
  test.test_number = 64;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5GLoTrvN1yU9GGeqeph3TeL2dseK5CVpdrWG26HDPVSM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BCYM5y7PwxUbrW1nvoeQhfKnkXcv2n9uDwJFXd2qgqQx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2V4uHeSXkWfy9csyuX7hyvfp9ECPPsVx4VA9PNjGCFza",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Mtjo4S3s4ToTNj8TNXArNVtwftj6XcKakxtJbiM8TSp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_64_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_64_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_64_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_64_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_64_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_64_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_65(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 432;
  test.test_number = 65;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CQ1snf1Pb8mNtae4RMVv5rV3XYfzY21tVfNrHmPY632U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FRB1rbCRMddUpkiSwrKJh2pwcRWc1ekHVDaw2g2d4qeB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7seq324UpZyafB3KuDeJJkyUvbPxus17ULZFV4mR8BMK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AoM3efyU7fxyP5pDFGwoZoJ2aMLLnbzodWCdpDRB8pmh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_65_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_65_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_65_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_65_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_65_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_65_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_66(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 18;
  test.test_number = 66;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5GLoTrvN1yU9GGeqeph3TeL2dseK5CVpdrWG26HDPVSM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BCYM5y7PwxUbrW1nvoeQhfKnkXcv2n9uDwJFXd2qgqQx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2V4uHeSXkWfy9csyuX7hyvfp9ECPPsVx4VA9PNjGCFza",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Mtjo4S3s4ToTNj8TNXArNVtwftj6XcKakxtJbiM8TSp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_66_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_66_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_66_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_66_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_66_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_66_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_67(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 472;
  test.test_number = 67;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5GLoTrvN1yU9GGeqeph3TeL2dseK5CVpdrWG26HDPVSM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BCYM5y7PwxUbrW1nvoeQhfKnkXcv2n9uDwJFXd2qgqQx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2V4uHeSXkWfy9csyuX7hyvfp9ECPPsVx4VA9PNjGCFza",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Mtjo4S3s4ToTNj8TNXArNVtwftj6XcKakxtJbiM8TSp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_67_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_67_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_67_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_67_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_67_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_67_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_68(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 512;
  test.test_number = 68;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5GLoTrvN1yU9GGeqeph3TeL2dseK5CVpdrWG26HDPVSM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BCYM5y7PwxUbrW1nvoeQhfKnkXcv2n9uDwJFXd2qgqQx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2V4uHeSXkWfy9csyuX7hyvfp9ECPPsVx4VA9PNjGCFza",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Mtjo4S3s4ToTNj8TNXArNVtwftj6XcKakxtJbiM8TSp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_68_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_68_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_68_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_68_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_68_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_68_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_69(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 35;
  test.test_number = 69;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CQ1snf1Pb8mNtae4RMVv5rV3XYfzY21tVfNrHmPY632U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FRB1rbCRMddUpkiSwrKJh2pwcRWc1ekHVDaw2g2d4qeB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7seq324UpZyafB3KuDeJJkyUvbPxus17ULZFV4mR8BMK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AoM3efyU7fxyP5pDFGwoZoJ2aMLLnbzodWCdpDRB8pmh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_69_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_69_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_69_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_69_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_69_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_69_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_70(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 504;
  test.test_number = 70;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CQ1snf1Pb8mNtae4RMVv5rV3XYfzY21tVfNrHmPY632U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FRB1rbCRMddUpkiSwrKJh2pwcRWc1ekHVDaw2g2d4qeB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7seq324UpZyafB3KuDeJJkyUvbPxus17ULZFV4mR8BMK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AoM3efyU7fxyP5pDFGwoZoJ2aMLLnbzodWCdpDRB8pmh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_70_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_70_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_70_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_70_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_70_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_70_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_71(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 547;
  test.test_number = 71;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CQ1snf1Pb8mNtae4RMVv5rV3XYfzY21tVfNrHmPY632U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FRB1rbCRMddUpkiSwrKJh2pwcRWc1ekHVDaw2g2d4qeB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7seq324UpZyafB3KuDeJJkyUvbPxus17ULZFV4mR8BMK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AoM3efyU7fxyP5pDFGwoZoJ2aMLLnbzodWCdpDRB8pmh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_71_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_71_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_71_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_71_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_71_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_71_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_72(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 266;
  test.test_number = 72;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5GLoTrvN1yU9GGeqeph3TeL2dseK5CVpdrWG26HDPVSM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BCYM5y7PwxUbrW1nvoeQhfKnkXcv2n9uDwJFXd2qgqQx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2V4uHeSXkWfy9csyuX7hyvfp9ECPPsVx4VA9PNjGCFza",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Mtjo4S3s4ToTNj8TNXArNVtwftj6XcKakxtJbiM8TSp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_72_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_72_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_72_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_72_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_72_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_72_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_73(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 537;
  test.test_number = 73;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "5GLoTrvN1yU9GGeqeph3TeL2dseK5CVpdrWG26HDPVSM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "BCYM5y7PwxUbrW1nvoeQhfKnkXcv2n9uDwJFXd2qgqQx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "2V4uHeSXkWfy9csyuX7hyvfp9ECPPsVx4VA9PNjGCFza",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "3Mtjo4S3s4ToTNj8TNXArNVtwftj6XcKakxtJbiM8TSp",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_73_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_73_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_73_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_73_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_73_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_73_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_74(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 26,29,82,80,112,78,123,33,56,76,118,15,24,110,79,126,27,122,61,116,77,87,83,75,124,89,128,103,90,120,113,106,105,125,111,108,92,117,121,55,114,62,109,127,2,30,98 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_authorize_delegated_stake::new_behavior";
  test.test_nonce  = 351;
  test.test_number = 74;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 7;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "CQ1snf1Pb8mNtae4RMVv5rV3XYfzY21tVfNrHmPY632U",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1000000000UL;
  test_acc->result_lamports = 1000000000UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "FRB1rbCRMddUpkiSwrKJh2pwcRWc1ekHVDaw2g2d4qeB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "7seq324UpZyafB3KuDeJJkyUvbPxus17ULZFV4mR8BMK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Vote111111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 100UL;
  test_acc->result_lamports = 100UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "AoM3efyU7fxyP5pDFGwoZoJ2aMLLnbzodWCdpDRB8pmh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 42UL;
  test_acc->result_lamports = 42UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_3_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_3_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_3_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_3_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarC1ock11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_4_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_4_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_4_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_4_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarStakeHistory1111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_5_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_5_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_5_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_5_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "StakeConfig11111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_74_acc_6_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_74_acc_6_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_74_acc_6_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_74_acc_6_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_74_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_74_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
