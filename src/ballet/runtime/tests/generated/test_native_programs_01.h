#include "../fd_tests.h"
int test_25(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,80,125,15,127,24,87,56,114,30,61,82,123,26,89,120,75,55,113,108,110,117,126,2,116,29,33,76,79,103,112,121,128,118,124,109,77,62,27,92,98,122,111,105,83,106,78 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 20;
  test.test_number = 25;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANFPuKmeR9jDeAFURRBpGdaXYgPhduuyFXiAvPpuem1p",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_25_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_25_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_25_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_25_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_25_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_25_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_25_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_25_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_25_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_25_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_25_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_25_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_25_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_25_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_26(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,80,125,15,127,24,87,56,114,30,61,82,123,26,89,120,75,55,113,108,110,117,126,2,116,29,33,76,79,103,112,121,128,118,124,109,77,62,27,92,98,122,111,105,83,106,78 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 28;
  test.test_number = 26;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANFPuKmeR9jDeAFURRBpGdaXYgPhduuyFXiAvPpuem1p",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_26_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_26_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_26_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_26_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_26_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_26_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_26_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_26_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111BTngbpkVTh3nGGdFdufHcG5TN7hXV6AfDy",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CfoVZ9eMbESQia3WiAfF4dtpFdUMcnvAB1",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_26_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_26_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_26_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_26_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_26_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_26_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_27(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,80,125,15,127,24,87,56,114,30,61,82,123,26,89,120,75,55,113,108,110,117,126,2,116,29,33,76,79,103,112,121,128,118,124,109,77,62,27,92,98,122,111,105,83,106,78 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates";
  test.test_nonce  = 31;
  test.test_number = 27;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ANFPuKmeR9jDeAFURRBpGdaXYgPhduuyFXiAvPpuem1p",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_27_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_27_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_27_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_27_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111B4T5ciTCkWauSqVAcVKy88ofjcSamrapud",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111CGTta3M4t3yXu8uRgkKvaWd2d8DQuZLKrf",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_27_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_27_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_27_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_27_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111Bs8Haw3nAsWf5hmLfKzc6PMEzcxUCKkVYK",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111D596YFweJQuHY1BbjazZYmAbt8jJL2VzVM",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_27_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_27_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_27_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_27_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_27_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_27_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_28(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,92,78,118,106,33,126,29,110,76,15,124,24,103,79,112,56,82,26,122,117,80,90,127,116,111,89,75,2,113,125,30,55,87,121,62,123,105,114,109,83,108,120,98,128,27,77 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 5;
  test.test_number = 28;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3gZAPkMkWKh6Vt7ky9kofk8r1bqNJBUPo2EjFJBXs7uF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_28_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_28_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_28_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_28_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_28_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_28_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_29(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,92,78,118,106,33,126,29,110,76,15,124,24,103,79,112,56,82,26,122,117,80,90,127,116,111,89,75,2,113,125,30,55,87,121,62,123,105,114,109,83,108,120,98,128,27,77 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 1;
  test.test_number = 29;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EWzLFny6gV3NsxV4E8ekXLMbCdop7zaYRJuxbaQZZnFU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_29_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_29_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_29_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_29_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_29_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_29_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_30(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,92,78,118,106,33,126,29,110,76,15,124,24,103,79,112,56,82,26,122,117,80,90,127,116,111,89,75,2,113,125,30,55,87,121,62,123,105,114,109,83,108,120,98,128,27,77 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 29;
  test.test_number = 30;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EWzLFny6gV3NsxV4E8ekXLMbCdop7zaYRJuxbaQZZnFU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_30_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_30_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_30_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_30_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_30_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_30_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_31(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 108,118,106,33,98,116,87,111,76,75,103,114,109,26,2,77,120,82,105,29,83,127,80,110,121,126,27,55,123,128,90,92,30,89,24,78,56,61,112,117,122,79,125,62,113,15,124 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 29;
  test.test_number = 31;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3gZAPkMkWKh6Vt7ky9kofk8r1bqNJBUPo2EjFJBXs7uF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_31_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_31_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_31_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_31_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_31_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_31_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_32(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,118,106,33,98,116,87,111,76,75,103,114,109,26,2,77,120,82,105,29,83,127,80,110,121,126,27,55,123,128,90,92,30,89,24,78,56,61,112,117,122,79,125,62,113,15,124 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 14;
  test.test_number = 32;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EWzLFny6gV3NsxV4E8ekXLMbCdop7zaYRJuxbaQZZnFU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_32_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_32_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_32_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_32_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_32_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_32_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_32_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_32_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_32_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_32_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_33(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 108,118,106,33,98,116,87,111,76,75,103,114,109,26,2,77,120,82,105,29,83,127,80,110,121,126,27,55,123,128,90,92,30,89,24,78,56,61,112,117,122,79,125,62,113,15,124 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 25;
  test.test_number = 33;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EWzLFny6gV3NsxV4E8ekXLMbCdop7zaYRJuxbaQZZnFU",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_33_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_33_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_33_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_33_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "11111117353mdUKehx9GW6JNHznGt5oSZs9fWkVkB",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "11111117SQekjmcMtR25wEPPiL6m1Mb5586NkLL4X",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_33_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_33_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_33_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_33_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_33_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_33_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_34(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 105,89,87,113,123,83,117,122,112,61,109,15,56,118,79,80,110,128,121,126,55,103,62,125,98,111,92,90,30,127,27,116,108,78,77,26,120,82,106,76,124,24,29,114,2,33,75 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 18;
  test.test_number = 34;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3gZAPkMkWKh6Vt7ky9kofk8r1bqNJBUPo2EjFJBXs7uF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_34_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_34_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_34_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_34_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_34_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_34_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_34_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_34_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_34_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_34_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_35(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 114,2,117,76,89,92,108,75,26,62,56,123,90,113,61,121,24,55,106,127,87,27,110,80,125,103,112,82,33,30,122,77,83,118,111,105,79,126,98,29,116,109,124,120,78,128,15 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_config_updates_requiring_config";
  test.test_nonce  = 26;
  test.test_number = 35;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 2;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3gZAPkMkWKh6Vt7ky9kofk8r1bqNJBUPo2EjFJBXs7uF",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_35_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_35_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_35_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_35_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "1111111DUUhXNEw1bNAMSKgm1Kt2tSPWdzF3G5poh",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "1111111DspJWUYDimq3AsTmnRfCX1iB99FBkVff83",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_35_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_35_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_35_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_35_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_35_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_35_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_36(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 56,124,83,80,62,78,117,116,127,24,123,110,120,125,105,113,106,89,79,55,128,121,33,76,77,75,122,29,109,26,118,98,92,112,2,90,111,114,103,30,61,87,82,108,27,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_create_ok";
  test.test_nonce  = 8;
  test.test_number = 36;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EzsMQf34mTyUjp3SYxvai9fgxVMPMZZv6KKkGcdBW2K5",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_36_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_36_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_36_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_36_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_36_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_36_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_37(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 56,124,83,80,62,78,117,116,127,24,123,110,120,125,105,113,106,89,79,55,128,121,33,76,77,75,122,29,109,26,118,98,92,112,2,90,111,114,103,30,61,87,82,108,27,126,15 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_create_ok";
  test.test_nonce  = 12;
  test.test_number = 37;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "EdcCWPzZbtWxXeN9Zks833Jz2BF5afzTsydCDKLPuSyr",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_37_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_37_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_37_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_37_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_37_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_37_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_38(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 128,116,56,98,80,27,112,117,82,15,89,114,110,106,26,55,29,127,120,87,61,123,125,30,83,75,124,24,103,79,121,33,77,105,62,108,113,78,90,76,109,92,111,2,118,122,126 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_account0_not_signer";
  test.test_nonce  = 1;
  test.test_number = 38;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9wifH4yYeHhAy8hKstRYpjupY2QJASAYtjC7E9g8K3cx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_38_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_38_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_38_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_38_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_38_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_38_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_39(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 128,116,56,98,80,27,112,117,82,15,89,114,110,106,26,55,29,127,120,87,61,123,125,30,83,75,124,24,103,79,121,33,77,105,62,108,113,78,90,76,109,92,111,2,118,122,126 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_account0_not_signer";
  test.test_nonce  = 6;
  test.test_number = 39;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2XXbzQjV4nQ3QbGZ8a7339CTa6EQoGyfHoxEia4dpva2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_39_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_39_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_39_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_39_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_39_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_39_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_40(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 113,27,83,117,120,87,116,79,62,127,80,125,111,110,112,108,89,55,56,124,92,78,2,105,114,77,106,33,123,126,30,76,109,24,26,122,61,82,29,98,75,15,103,90,118,128,121 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_account0_not_signer";
  test.test_nonce  = 14;
  test.test_number = 40;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9wifH4yYeHhAy8hKstRYpjupY2QJASAYtjC7E9g8K3cx",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_40_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_40_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_40_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_40_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_40_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_40_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_41(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 113,27,83,117,120,87,116,79,62,127,80,125,111,110,112,108,89,55,56,124,92,78,2,105,114,77,106,33,123,126,30,76,109,24,26,122,61,82,29,98,75,15,103,90,118,128,121 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_account0_not_signer";
  test.test_nonce  = 15;
  test.test_number = 41;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "2XXbzQjV4nQ3QbGZ8a7339CTa6EQoGyfHoxEia4dpva2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_41_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_41_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_41_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_41_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_41_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_41_raw_sz;
  test.expected_result = -8;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_42(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 106,118,105,89,128,30,110,77,27,111,98,122,124,26,15,2,29,33,80,79,127,112,114,78,125,113,123,117,90,126,92,116,109,103,87,62,121,56,83,120,82,76,108,55,75,61,24 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_instruction_data_too_large";
  test.test_nonce  = 17;
  test.test_number = 42;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3DA91Bxf9gy6ZxaiFxUTfvGh54vkrmFPpSCgebHMkDYa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_42_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_42_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_42_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_42_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_42_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_42_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_43(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 106,118,105,89,128,30,110,77,27,111,98,122,124,26,15,2,29,33,80,79,127,112,114,78,125,113,123,117,90,126,92,116,109,103,87,62,121,56,83,120,82,76,108,55,75,61,24 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_instruction_data_too_large";
  test.test_nonce  = 19;
  test.test_number = 43;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DXSpM226mZ9XzjjHnFrmMUSe7xj5CbvSsdXYZVgkccrg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_43_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_43_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_43_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_43_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_43_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_43_raw_sz;
  test.expected_result = -3;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_44(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 116,33,111,117,122,114,109,80,55,125,61,113,127,24,92,75,77,26,112,79,2,15,56,87,103,89,110,128,98,83,30,82,78,126,90,124,76,120,29,118,62,108,123,105,106,121,27 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_instruction_data_too_large";
  test.test_nonce  = 4;
  test.test_number = 44;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "3DA91Bxf9gy6ZxaiFxUTfvGh54vkrmFPpSCgebHMkDYa",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_44_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_44_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_44_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_44_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_44_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_44_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_45(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 116,33,111,117,122,114,109,80,55,125,61,113,127,24,92,75,77,26,112,79,2,15,56,87,103,89,110,128,98,83,30,82,78,126,90,124,76,120,29,118,62,108,123,105,106,121,27 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_fail_instruction_data_too_large";
  test.test_nonce  = 7;
  test.test_number = 45;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "DXSpM226mZ9XzjjHnFrmMUSe7xj5CbvSsdXYZVgkccrg",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_45_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_45_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_45_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_45_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_45_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_45_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_46(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 87,111,56,76,123,124,118,110,120,105,89,92,126,113,108,33,116,26,62,106,29,27,98,127,83,30,117,75,103,2,79,78,90,121,55,114,80,82,122,125,109,128,61,24,77,112,15 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_ok";
  test.test_nonce  = 11;
  test.test_number = 46;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6FuNEtMrtDmCAaPcZ8vxFZGSARh2yTpptLFNM54EPwuM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_46_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_46_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_46_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_46_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_46_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_46_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_47(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 87,111,56,76,123,124,118,110,120,105,89,92,126,113,108,33,116,26,62,106,29,27,98,127,83,30,117,75,103,2,79,78,90,121,55,114,80,82,122,125,109,128,61,24,77,112,15 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_ok";
  test.test_nonce  = 10;
  test.test_number = 47;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9q5WBv6AEvPHABxvrUHCYB94C9aFEmDMsbokE7ZeNkee",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_47_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_47_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_47_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_47_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_47_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_47_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_48(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 61,27,116,117,87,82,89,62,98,121,2,114,124,79,56,108,111,78,76,126,92,109,122,103,110,118,75,90,55,15,128,29,123,77,105,106,83,113,33,120,112,80,127,125,30,24,26 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_ok";
  test.test_nonce  = 22;
  test.test_number = 48;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "6FuNEtMrtDmCAaPcZ8vxFZGSARh2yTpptLFNM54EPwuM",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_48_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_48_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_48_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_48_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_48_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_48_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_49(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 61,27,116,117,87,82,89,62,98,121,2,114,124,79,56,108,111,78,76,126,92,109,122,103,110,118,75,90,55,15,128,29,123,77,105,106,83,113,33,120,112,80,127,125,30,24,26 };
  test.disable_feature = disabled_features;
  test.test_name = "config_processor::tests::test_process_store_ok";
  test.test_nonce  = 22;
  test.test_number = 49;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 1;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "9q5WBv6AEvPHABxvrUHCYB94C9aFEmDMsbokE7ZeNkee",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_49_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_49_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_49_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_49_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Config1111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_49_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_49_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
