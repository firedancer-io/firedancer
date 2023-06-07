#include "../fd_tests.h"
int test_650(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 1;
  uchar disabled_features[] = { 89 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 93;
  test.test_number = 650;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "ENyvk3wQJTk9U2LGvNCv29mtTTet7QKAfZxV4XAvYrES",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_650_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_650_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_650_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_650_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "8NuCUBUQtaKUDaxv7qvhJvoziMdMqNnHnrKCW8iSYCZP",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_650_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_650_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_650_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_650_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_650_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_650_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_650_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_650_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_650_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_650_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_651(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,124,120,103,30,105,113,55,92,128,118,27,125,114,127,56,77,89,15,61,29,79,110,26,83,78,106,111,123,112,108,116,109,87,121,98,76,82,117,90,24,33,62,80,126,75,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 116;
  test.test_number = 651;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "dGVnFPvXC5yoWhtYegQ8j8331WC7r1ZKWWpGDSagimk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_651_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_651_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_651_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_651_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "21YKAXRZ8Ve342jBo5qA47gqPy1bH4nCYP6fmd2yGzhN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_651_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_651_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_651_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_651_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_651_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_651_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_651_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_651_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_651_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_651_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_652(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,124,120,103,30,105,113,55,92,128,118,27,125,114,127,56,77,89,15,61,29,79,110,26,83,78,106,111,123,112,108,116,109,87,121,98,76,82,117,90,24,33,62,80,126,75,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 162;
  test.test_number = 652;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "dGVnFPvXC5yoWhtYegQ8j8331WC7r1ZKWWpGDSagimk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_652_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_652_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_652_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_652_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "21YKAXRZ8Ve342jBo5qA47gqPy1bH4nCYP6fmd2yGzhN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 4565761UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_652_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_652_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_652_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_652_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_652_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_652_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_652_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_652_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_652_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_652_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_653(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,124,120,103,30,105,113,55,92,128,118,27,125,114,127,56,77,89,15,61,29,79,110,26,83,78,106,111,123,112,108,116,109,87,121,98,76,82,117,90,24,33,62,80,126,75,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 176;
  test.test_number = 653;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "dGVnFPvXC5yoWhtYegQ8j8331WC7r1ZKWWpGDSagimk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_653_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_653_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_653_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_653_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "21YKAXRZ8Ve342jBo5qA47gqPy1bH4nCYP6fmd2yGzhN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 4565762UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_653_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_653_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_653_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_653_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_653_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_653_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_653_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_653_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_653_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_653_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_654(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,124,120,103,30,105,113,55,92,128,118,27,125,114,127,56,77,89,15,61,29,79,110,26,83,78,106,111,123,112,108,116,109,87,121,98,76,82,117,90,24,33,62,80,126,75,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 64;
  test.test_number = 654;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "dGVnFPvXC5yoWhtYegQ8j8331WC7r1ZKWWpGDSagimk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_654_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_654_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_654_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_654_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "21YKAXRZ8Ve342jBo5qA47gqPy1bH4nCYP6fmd2yGzhN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 2282881UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_654_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_654_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_654_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_654_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_654_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_654_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_654_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_654_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_654_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_654_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_655(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 2,124,120,103,30,105,113,55,92,128,118,27,125,114,127,56,77,89,15,61,29,79,110,26,83,78,106,111,123,112,108,116,109,87,121,98,76,82,117,90,24,33,62,80,126,75,122 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_100_percent_of_source_to_account_with_lamports::old_behavior";
  test.test_nonce  = 97;
  test.test_number = 655;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "dGVnFPvXC5yoWhtYegQ8j8331WC7r1ZKWWpGDSagimk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282881UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_655_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_655_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_655_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_655_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "21YKAXRZ8Ve342jBo5qA47gqPy1bH4nCYP6fmd2yGzhN",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 4565760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_655_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_655_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_655_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_655_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_655_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_655_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_655_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_655_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_655_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_655_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_656(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 165;
  test.test_number = 656;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_656_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_656_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_656_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_656_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1005261759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_656_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_656_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_656_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_656_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_656_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_656_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_656_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_656_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_656_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_656_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_657(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 191;
  test.test_number = 657;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_657_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_657_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_657_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_657_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1005261760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_657_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_657_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_657_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_657_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_657_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_657_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_657_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_657_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_657_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_657_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_658(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 233;
  test.test_number = 658;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_658_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_658_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_658_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_658_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 2005261759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_658_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_658_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_658_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_658_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_658_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_658_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_658_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_658_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_658_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_658_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_659(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 288;
  test.test_number = 659;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_659_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_659_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_659_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_659_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2005261760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_659_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_659_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_659_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_659_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_659_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_659_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_659_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_659_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_659_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_659_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_660(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 87;
  test.test_number = 660;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_660_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_660_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_660_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_660_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_660_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_660_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_660_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_660_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_660_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_660_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_660_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_660_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_660_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_660_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_661(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 104;
  test.test_number = 661;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_661_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_661_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_661_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_661_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_661_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_661_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_661_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_661_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_661_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_661_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_661_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_661_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_661_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_661_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_662(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 157;
  test.test_number = 662;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_662_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_662_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_662_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_662_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 1005261759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_662_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_662_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_662_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_662_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_662_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_662_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_662_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_662_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_662_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_662_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_663(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 202;
  test.test_number = 663;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_663_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_663_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_663_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_663_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 1005261760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_663_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_663_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_663_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_663_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_663_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_663_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_663_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_663_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_663_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_663_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_664(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 249;
  test.test_number = 664;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_664_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_664_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_664_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_664_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 2005261759UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_664_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_664_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_664_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_664_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_664_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_664_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_664_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_664_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_664_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_664_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_665(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 289;
  test.test_number = 665;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 1002978880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_665_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_665_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_665_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_665_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 2005261760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_665_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_665_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_665_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_665_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_665_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_665_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_665_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_665_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_665_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_665_raw_sz;
  test.expected_result = 0;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_666(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 123;
  test.test_number = 666;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_666_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_666_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_666_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_666_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_666_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_666_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_666_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_666_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_666_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_666_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_666_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_666_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_666_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_666_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_667(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 174;
  test.test_number = 667;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_667_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_667_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_667_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_667_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_667_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_667_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_667_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_667_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_667_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_667_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_667_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_667_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_667_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_667_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_668(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 208;
  test.test_number = 668;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_668_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_668_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_668_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_668_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_668_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_668_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_668_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_668_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_668_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_668_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_668_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_668_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_668_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_668_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_669(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 248;
  test.test_number = 669;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_669_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_669_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_669_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_669_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_669_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_669_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_669_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_669_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_669_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_669_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_669_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_669_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_669_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_669_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_670(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 47;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 50;
  test.test_number = 670;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "WQZhzhFbhdcwwb46t4zGNXri1WFYhNqdoQ2yWqR8GVc",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_670_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_670_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_670_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_670_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HGgQR9ndQkfUoutRcteNE5C8dP2RqgQRFiy6B2jSW9gm",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 0UL;
  test_acc->result_lamports = 0UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_670_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_670_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_670_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_670_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_670_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_670_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_670_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_670_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_670_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_670_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_671(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 122;
  test.test_number = 671;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_671_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_671_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_671_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_671_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282879UL;
  test_acc->result_lamports = 2282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_671_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_671_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_671_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_671_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_671_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_671_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_671_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_671_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_671_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_671_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_672(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 181;
  test.test_number = 672;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_672_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_672_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_672_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_672_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2282880UL;
  test_acc->result_lamports = 2282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_672_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_672_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_672_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_672_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_672_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_672_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_672_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_672_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_672_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_672_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_673(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 217;
  test.test_number = 673;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_673_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_673_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_673_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_673_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282879UL;
  test_acc->result_lamports = 1002282879UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_673_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_673_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_673_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_673_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_673_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_673_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_673_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_673_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_673_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_673_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
int test_674(fd_executor_test_suite_t *suite) {
  fd_executor_test_t test;
  fd_memset( &test, 0, FD_EXECUTOR_TEST_FOOTPRINT );
  test.disable_cnt = 0;
  uchar disabled_features[] = { 90,120,103,121,112,79,124,33,125,114,98,82,126,87,62,76,108,116,29,27,109,77,118,128,26,75,24,122,80,113,117,56,110,89,127,123,30,55,105,15,78,83,106,111,2,61,92 };
  test.disable_feature = disabled_features;
  test.test_name = "stake_instruction::tests::test_split_from_larger_sized_account::new_behavior";
  test.test_nonce  = 265;
  test.test_number = 674;
  if (fd_executor_test_suite_check_filter(suite, &test)) return -9999;
  ulong test_accs_len = 3;
  fd_executor_test_acc_t* test_accs = fd_alloca( 1UL, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );
  fd_memset( test_accs, 0, FD_EXECUTOR_TEST_ACC_FOOTPRINT * test_accs_len );

  fd_executor_test_acc_t* test_acc = test_accs;
  fd_base58_decode_32( "FJ57JsuFVjuoJDHuwBpp7TWGCErMcBTjf3pbKpcugkYk",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 2005957760UL;
  test_acc->result_lamports = 2005957760UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_674_acc_0_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_674_acc_0_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_674_acc_0_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_674_acc_0_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "HkcvgPDLL6HMQnYseNp4Lpaeb1obrdgP62onUrasgTf2",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1002282880UL;
  test_acc->result_lamports = 1002282880UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_674_acc_1_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_674_acc_1_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_674_acc_1_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_674_acc_1_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "SysvarRent111111111111111111111111111111111",  (uchar *) &test_acc->pubkey);
  fd_base58_decode_32( "Sysvar1111111111111111111111111111111111111",  (uchar *) &test_acc->owner);
  test_acc->lamports        = 1UL;
  test_acc->result_lamports = 1UL;
  test_acc->executable      = 0;
  test_acc->rent_epoch      = 0;
  test_acc->data            = fd_flamenco_native_prog_test_674_acc_2_data;
  test_acc->data_len        = fd_flamenco_native_prog_test_674_acc_2_data_sz;
  test_acc->result_data     = fd_flamenco_native_prog_test_674_acc_2_post_data;
  test_acc->result_data_len = fd_flamenco_native_prog_test_674_acc_2_post_data_sz;
  test_acc++;

  fd_base58_decode_32( "Stake11111111111111111111111111111111111111",  (unsigned char *) &test.program_id);
  test.raw_tx = fd_flamenco_native_prog_test_674_raw;
  test.raw_tx_len = fd_flamenco_native_prog_test_674_raw_sz;
  test.expected_result = -6;
  test.custom_err = 0;

  test.accs_len = test_accs_len;
  test.accs = test_accs;

  return fd_executor_run_test( &test, suite );
}
